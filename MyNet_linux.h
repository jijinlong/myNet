//
//  MyNet.h
//  Dragon
//
//  Created by GameDeveloper on 13-10-20.
//
//

#ifndef Dragon_MyNet_h
#define Dragon_MyNet_h
#include "platfrom.h"
#if PLATFORM == PLATFORM_UNIX
#include "zlib.h"
#include <vector>
#include <string>
#include <list>
/**
 * 特别针对于lua设计
 */
namespace mynet{
    /**
     ******************************** 2进制缓存器******************************
     *
     * Buffer 中获取信息后 会重置当前位置
     */
    class Record{
    public:
        Record(void *cmd,unsigned int len)
        {
            contents = new unsigned char[len];
            memcpy(contents,cmd,len);
            contentSize = len;
            offset = 0;
        }
        Record()
        {
            offset = 0;
            contentSize = 0;
            contents = NULL;
        }
        ~Record()
        {
            if (contents) delete contents;
            contents = NULL;
        }
        unsigned int recv(void *buffer,unsigned int len)
        {
            if (empty()) return 0;
            len = leftsize() < len ? leftsize(): len;
            memcpy(buffer,contents + offset,len);
            offset += len;
            return len;
        }
        unsigned int leftsize()
        {
            return contentSize - offset;
        }
        template<class CONNECTION>
        bool sendOver(CONNECTION *connection)
        {
            unsigned int leftSize = leftsize();
            if ( 0 == leftSize) return true;
            int sendLen = connection->send(contents + offset,leftSize);
            offset += sendLen;
            if (sendLen < leftSize) return false;
            return true;
        }
        unsigned int offset;
        bool empty()
        {
            return offset == contentSize;
        }
        unsigned int contentSize;
        unsigned char *contents;
    };
    /**
     * ****************************线程安全的消息队列************************
     */
    template<typename CLASS>
    class Node{
    public:
        CLASS node;
        Node<CLASS> *next;
        Node()
        {
            next = NULL;
        }
    };
    template<typename CLASS>
    class MyList{
    public:
        Node<CLASS> *readPointer;
        Node<CLASS> *writePointer;
        
        MyList()
        {
            writePointer = new Node<CLASS>();
            readPointer = writePointer;
        }
        void write(CLASS object)
        {
            if (writePointer)
            {
                writePointer->node = object;
                Node<CLASS> * node = new Node<CLASS>();
                writePointer->next = node;
                writePointer = node;
            }
        }
        bool empty()
        {
            if (readPointer == writePointer) return true;
            return false;
        }
        bool readOnly(CLASS &object)
        {
            if (empty()) return false;
            object = readPointer->node;
            return true;
        }
        bool readAndPop(CLASS &object)
        {
            if (readPointer == writePointer) return false;
            object = readPointer->node;
            Node<CLASS> * node = readPointer;
            readPointer = readPointer->next;
            delete node;
            return true;
        }
        bool pop()
        {
            if (readPointer == writePointer) return false;
            Node<CLASS> * node = readPointer;
            readPointer = readPointer->next;
            delete node;
            return true;
        }
        ~MyList()
        {
            if (writePointer)
            {
                delete writePointer;
            }
            writePointer = NULL;
        }
    };
    /**
     * *************************解码处理函数*****************************************
     */
    struct stGetPackage{
        virtual void doGetCommand(void *cmd,unsigned int len) = 0;
    };
    /**
     * 解码器
     */
    class Decoder{
    public:
        Decoder(){
            currentoffset = 0;
            nowstate = 0;
            tag = 0;
        }
    private:
        unsigned int currentoffset; // ÂΩìÂâçÊï∞ÊçÆËµ∑ÂßãÁÇ?
        std::vector<unsigned char> contents;
        
        enum{
            START,
            END,
            PICK_HEAD,
            PICK_BODY,
        };
        
        unsigned char nowstate; //
        unsigned char tag; //
        static const unsigned int MAX_DATASIZE = 65536; //
        enum{
            ZIP = 1 << 0, // ZIP
            DES = 1 << 1, // DES
            MIN_HEAD = 1 << 2, //
            MAX_HEAD = 1 << 3, //
        };
        
        unsigned leftsize();
        template<typename Record>
        bool pickdata(Record *record)
        {
            unsigned int left_size = leftsize();
            if (left_size == 0) return true;
            int ret = record->recv(&contents[currentoffset],left_size);
            if (ret < left_size)
            {
                currentoffset += ret;
                return false;
            }
            currentoffset += ret;
            return true;
        }
        void refresh();
        template<typename Record>
        bool run(Record *record)
        {
            if ( currentoffset == contents.size())
            {
                refresh();
                return pickdata(record) || isFinished();
            }
            return pickdata(record);
        }
        bool isFinished();
        void setbodysize(unsigned int size);
        unsigned int getbodysize();
    public:
        template<typename Record>
        unsigned int decode(Record * target,void *buffer,unsigned int maxSize) // Ëß£Á†ÅÂô?
        {
            while(run(target))
            {
                if (isFinished())
                {
                    undes();
                    unsigned int retSize = unzip((unsigned char*)buffer,maxSize,0);
                    return retSize;
                }
            }
            return 0;
        }
        template<typename Record>
        void decode(Record *target,stGetPackage *callback) // Ëß£Á†ÅÂô?
        {
            while(run(target))
            {
                if (isFinished())
                {
                    undes();
                    if (tag & ZIP)
                    {
                        unsigned char buffer[MAX_DATASIZE]={'\0'};
                        unsigned int retSize = unzip(buffer,MAX_DATASIZE,0);
                        if (callback)
                            callback->doGetCommand(buffer,retSize);
                    }
                    else if (contents.size())
                    {
                        if (callback)
                            callback->doGetCommand(&contents[0],contents.size());
                    }
                }
            }
        }
        Record * getRecord();
        void encode(void *data,unsigned int len,bool ziptag = false,bool destag = false);
    private:
        unsigned int unzip_size(unsigned int zip_size);
        unsigned int unzip(unsigned char *buffer,unsigned int len,unsigned int offset);
        
        void undes();
        unsigned int zip(void *data,unsigned int len,unsigned int offset);
		
        void des();
    };
    /**
     * *****************************消息转发器***********************************
     * obj.req({reqId=1,retId=2,data={content="hello,world"}},function(jsondata)
     *
     * end)
     * 这里处理为 回调函数 并可以传入携带的object
     */
    class MsgFuncHandler{
    public:
        /**
         * 调用器
         * \param delegate 代理
         * \paran object 对象
         */
        virtual void call(void* cmd,unsigned int cmdLen){
            
        }
    };
    /**
     * 子类函数 包容函数
     */
    template<class CLASS>
    class MsgFunction:public MsgFuncHandler{
    private:
        typedef int (CLASS::*Handle)(void* cmd,unsigned int cmdLen);
        Handle handle1;
        CLASS *object;
    public:
        /**
         * 使用1号方式构建
         * (Socket *,int ,void*)
         */
        MsgFunction(CLASS *object,Handle handle):object(object),handle1(handle){}
        
        /**
         * 调用器
         * \param delegate 代理
         * \paran object 对象
         */
        virtual void call(void* cmd,unsigned int cmdLen){
            if (object) // 校验
            {
                ((*object).*handle1)(cmd,cmdLen);
            }
        }
    };
    
    /**
     * 处理消息
     */
    class Handles{
    public:
        /**
         * 增加消息处理的句柄
         * \param type 消息类型
         * \param T_HANDLE handle 处理句柄
         **/
        bool addHandle(unsigned short type,MsgFuncHandler* handle);
        /**
         * 处理消息
         * \param object 对象
         * \param cmd 消息
         * \param len 消息长度
         **/
        bool handle(unsigned short type,void*cmd,unsigned int cmdLen);
    private:
        std::vector<MsgFuncHandler*> tables;
    };
    /**
     *********************** Pool处理器*******************************
     **/
    
	enum EVENT_TYPE{
		ACCEPT_EVT = 1 << 0, 
		OUT_EVT = 1 << 1, 
		IN_EVT = 1 << 2,
		ERROR_EVT = 1 << 3,
	};
	class EventBase;
	class Target{
	public:
		virtual int getHandle() = 0;
		virtual int getPeerHandle() {return -1;}
		EventBase *evt;
		Target(){evt = NULL;}
	};
	class EventBase{
	public:
		EventBase(Target *target):target(target)
		{}
		Target *target;
		int eventType;	
		struct epoll_event ev;
		int poolHandle;
		virtual void deal(int eventType);
		void set(int eventType);
		virtual void stopWrite();
		void startRead();
		void stopRead();
		void startWrite();
		int getPeerHandle();
		bool isOut();
		bool isIn();
		bool isErr();
		bool isAccept();
		const static unsigned int MAX_BUFFER_LEN = 65000;
	};
	template<typename TARGET>
	class Event:public EventBase{
	public:
		Event(TARGET *target):EventBase(target)
		{}
		TARGET * operator->()
		{
			return (TARGET*)target;
		}
	};
	struct _epoll_event{
		int u;
		long l;
	};
	class EventPool{
	public:
		EventPool()
		{
		}
		void init();
		void bindEvent(Target *target,int eventType);
		std::vector<struct _epoll_event> eventBuffer;
		int poolHandle;
		EventBase *pullEvent();
	};
	// NET
	class Connection:public pool::Target,public stGetPackage{
	 public:
		std::string peerIp;
		unsigned short peerPort;
		virtual bool destroy();
		virtual void doGetCommand(void *cmd,unsigned int len){}
		Connection()
		{
			peerPort = 0;
			directDealCmd = true;
		}
		int getHandle(){return socket;}
		void setHandle(int socket){this->socket = socket;}
		void sendCmd(void *cmd,unsigned int len);
		void sendBuffer(void *cmd,unsigned int len);
		int send(void *cmd,unsigned int len);
		template<class CmdObject>
		void sendObject(CmdObject *object)
		{
			cmd::Stream ss;
			object->toStream(ss);
			if (ss.size())
			{
			Decoder decoder;
			decoder.encode(ss.content(),ss.size());
			Record * record = decoder.getRecord();
			printf("发送逻辑层数据:%d 大小:%u\n",object->__msg__id__,record->contentSize);

			sends.write(record);
			if (evt)
				evt->startWrite();	
			}
		}
		void recvCmdCallback(void *cmd,unsigned int len)
		{}
		Decoder decoder;
		bool directDealCmd;
		/** 
		* 
		*/
		unsigned int getCmd(void *cmd,unsigned int len)
		{
			return decoder.decode(this,cmd,len);
		}
		/**
		* 
		**/
		unsigned int recv(void *cmd,unsigned int size);
		char buffer[pool::EventBase::MAX_BUFFER_LEN];
		virtual void doReadBuffer(pool::EventBase *evt,stGetPackage *callback = NULL);

		/**
		**/
		virtual void doRead(pool::EventBase *evt,stGetPackage *callback = NULL);
		void httpGet(const std::string &url)
		{
		}
		/**
		* ÔÚpool ÖÐ´¦Àí·¢ËÍ
		**/
		virtual void doSend(pool::EventBase *evt);
		int  socket;
		// std::list<Record*> recvs;
		MyList<Record*> recvs;
		// std::list<Record*> sends;
		MyList<Record*> sends;
	 };
	 class Client:public Connection{
	 public:
		Client(){}
		 Client(const char *ip,unsigned short port)
		 {
			init(ip,port);
		 }
		 void init(const char *ip,unsigned short port);
		 int getHandle(){return socket;}
		 struct sockaddr_in addrServer;
		 void setnonblock(int socket);
 		virtual bool destroy();
	 };
	 class Server:public pool::Target{
	 public:
		Server(const char *ip,unsigned short port)
		{
			init(ip,port);
		}
		void init(const char *ip,unsigned short port);
		void setnonblock(int socket);
		int getPeerHandle();
		template<class CONNECTION>
		CONNECTION *getConnection()
		{
			socklen_t clilen = 1024;
			struct sockaddr_in addr;
			int con = ::accept(socket,(struct sockaddr*)(&addr),&clilen);	
			setnonblock(con);
			CONNECTION *conn =  new CONNECTION();
			conn->peerIp = inet_ntoa(addr.sin_addr);
			conn->peerPort = ntohs(addr.sin_port);

			conn->setHandle(con);
			printf("accept:ip:%sport:%u",inet_ntoa(addr.sin_addr),ntohs(addr.sin_port));

			return conn;
		}
		int getHandle(){return socket;}
		int socket;
	 };
}

#endif
#endif
