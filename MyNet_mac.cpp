//
//  MyNet.cpp
//  Dragon
//
//  Created by GameDeveloper on 13-10-20.
//
//

#include "MyNet_mac.h"
#if PLATFORM == PLATFORM_APPLE
#include "sys/socket.h"
#include <sys/time.h>
#include "sys/poll.h"
#include "sys/select.h"
#include "sys/types.h"
#include "netinet/in.h"
#include "fcntl.h"
#include "netdb.h"
#include "signal.h"
#include "memory.h"
#include <arpa/inet.h>
#include <pthread.h>
#include "strings.h"
#include "iconv.h"
#include <strings.h>
#include "unistd.h"
#include "poll.h"
#include "sys/event.h"
#include <sys/types.h>

namespace mynet {
    /**
     * *******************decoder 处理器**********************
     */
    unsigned Decoder::leftsize()
	{
		return contents.size() -currentoffset;
	}
	void Decoder::refresh()
	{
		//
		switch(nowstate)
		{
			case START:
			{
				contents.resize(1);
				nowstate = PICK_HEAD;
				currentoffset = 0;
				tag = 0;
			}break;
			case PICK_HEAD:
			{
				tag = contents[0];
				if (tag & MIN_HEAD)
					contents.resize(1);
				else if (tag & MAX_HEAD)
					contents.resize(2);
				else
					printf("Decorder::refresh error %d\n",tag);
				nowstate = PICK_BODY;
				currentoffset = 0;
			}break;
			case PICK_BODY:
			{
				contents.resize(getbodysize());
				nowstate = END;
				currentoffset = 0;
				//printf("Will take body.size():%u\n",contents.size());
			}break;
			case END:
			{
				nowstate = START;
				contents.resize(0);
				currentoffset = 0;
				tag = 0;
			}break;
		}
	}
	bool Decoder::isFinished()
	{
		// ÂÆåÊï¥Êä•Êñá‰∫?
		return ((nowstate==END) && leftsize() == 0);
	}
	void Decoder::setbodysize(unsigned int size)
	{
		if (tag & MIN_HEAD)
		{
			*(unsigned char*)(&contents[1]) = size;
		}
		if (tag & MAX_HEAD)
		{
			*(unsigned short*)(&contents[1]) = size;
		}
	}
	unsigned int Decoder::getbodysize()
	{
		if (tag & MIN_HEAD)
		{
			return *(unsigned char*)&contents[0];
		}
		if (tag & MAX_HEAD)
		{
			return *(unsigned short*)&contents[0];
		}
		return 0;
	}
	Record * Decoder::getRecord()
	{
		Record *record = new Record(&contents[0],contents.size());
		return record;
	}
	void Decoder::encode(void *data,unsigned int len,bool ziptag,bool destag) // ÊâìÂåÖÂô?
	{
		// ËÆæÁΩÆtag
		tag = 0;
		unsigned int headcontent = 0;
		if (len <= 255)
		{
			tag |= MIN_HEAD;
			ziptag = false; // Â∞èÊä•ÊñáÂº∫Âà∂‰∏çÊâìÂåÖ
			headcontent = 1; // ‰∏Ä‰∏™Â≠óËäÇÈïøÂ∫¶ÁöÑÊä•Êñá
		}
		else
		{
			tag |= MAX_HEAD;
			headcontent = 2;
		}
		if (ziptag) tag |= ZIP;
		if (destag) tag |= DES;
		
		if (ziptag)
		{
			len = zip(data,len,headcontent + 1);
		}
		else
		{
			contents.resize(len + headcontent + 1);
			memcpy(&contents[headcontent+1],data,len);
		}
		if (destag)
		{
			des();
		}
		
		contents[0] = tag;
		setbodysize(len);
	}
	unsigned int Decoder::unzip_size(unsigned int zip_size)
	{
		return zip_size * 120 / 100 + 12;
	}
	unsigned int Decoder::unzip(unsigned char *buffer,unsigned int len,unsigned int offset)
	{
		// Ëß£Âéã
		if (tag & ZIP)
		{
			unsigned int unZipLen = len;
			int retcode = uncompress(buffer,(uLongf*)&unZipLen,&contents[offset],contents.size() - offset);
			return unZipLen;
		}
		return 0;
	}
	
	void Decoder::undes()
	{
		// Ëß£ÂØÜ
		if (tag & DES)
		{
			
		}
	}
	unsigned int Decoder::zip(void *data,unsigned int len,unsigned int offset)
	{
		if (tag & ZIP)
		{
			contents.resize(unzip_size(len));
			unsigned int outlen = 0;
			int retcode = compress(&contents[offset],(uLongf*)&outlen,(const Bytef *)data,len);
			contents.resize(outlen);
			len = outlen;
		}
		return len;
	}
	
	void Decoder::des()
	{
		if (tag & DES)
		{
			
		}
	}
    /**
     * *******************处理消息**************************
     */
    /**
	 * 增加消息处理的句柄
	 * \param type 消息类型
	 * \param T_HANDLE handle 处理句柄
	 **/
	bool Handles::addHandle(unsigned short type,MsgFuncHandler* handle)
	{
		if (type >= tables.size())
		{
			tables.resize(type + 1);
		}
		if (tables[type]) return false;
		tables[type] = handle;
		return true;
	}
	/**
	 * 处理消息
	 * \param object 对象
	 * \param cmd 消息
	 * \param len 消息长度
	 **/
	bool Handles::handle(unsigned short type,void*cmd,unsigned int cmdLen)
    {
		MsgFuncHandler *h = NULL;
		if (type >= tables.size())
		{
			return false;
		}
		h =  tables[type];
		if (h) {
			h->call(cmd,cmdLen);
			return true;
		}
		return false;
    }
    /**
     * Pool 处理器
     **/
    void EventBase::delEevnt(int eventType)
    {
        if ((eventType & IN_EVT) | (ACCEPT_EVT & eventType))
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_READ, EV_DELETE, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
            this->eventType &= ~IN_EVT;
        }
        if (eventType & OUT_EVT)
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_WRITE,EV_DELETE, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
            this->eventType &= ~OUT_EVT;
        }
    }
    void EventBase::addEvent(int eventType)
    {
        //this->eventType |= eventType;
        if ((eventType & IN_EVT) | (ACCEPT_EVT & eventType))
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_READ, EV_ADD, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
        }
        if (eventType & OUT_EVT)
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_WRITE,EV_ADD, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
        }
    }
    void EventBase::disableEvent(int eventType)
    {
        //this->eventType |= eventType;
        if ((eventType & IN_EVT) | (ACCEPT_EVT & eventType))
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_READ, EV_DISABLE, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
        }
        if (eventType & OUT_EVT)
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_WRITE,EV_DISABLE, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
        }
    }
    void EventBase::enableEvent(int eventType)
    {
        //this->eventType |= eventType;
        if ((eventType & IN_EVT) | (ACCEPT_EVT & eventType))
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_READ, EV_ENABLE, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
        }
        if (eventType & OUT_EVT)
        {
            struct kevent kevts[1];
            EV_SET(&kevts[0], target->getHandle(), EVFILT_WRITE,EV_ENABLE, 0, 0, this);
            kevent(poolHandle, kevts, 1, NULL, 0, NULL);
        }
    }
    
    bool EventBase::isOut()
    {
        return eventType & OUT_EVT;
    }
    
    bool EventBase::isIn(){
        return eventType & IN_EVT;
    }
    
    bool EventBase::isErr()
    {
        return eventType & ERR_EVT;
    }
    int EventBase::getPeerHandle()
    {
        return target->getPeerHandle();
    }
    
    void EventBase::startRead()
    {
        enableEvent(IN_EVT);
    }
    
    void EventBase::stopWrite()
    {
        disableEvent(OUT_EVT);
    }
    void EventBase::startWrite()
    {
        enableEvent(OUT_EVT);
    }
    /**
     * EventPool
     */
    void EventPool::init()
    {
        poolHandle = kqueue();
        index = 0;
        maxCount = 0;
    }
    void EventPool::bindEvent(Target *target,int eventType)
    {
        Event<Target> *evt = new Event<Target>(target);
        target->evt = evt;
        evt->poolHandle = poolHandle;
        evt->addEvent(eventType);
    }
    static const unsigned int MAX_EVENT_COUNT = 100;
    EventBase * EventPool::pullEvent()
    {
        if (index == maxCount)
        {
            maxCount = kevent(poolHandle, NULL, 0, (struct kevent *)events, MAX_EVENT_COUNT, NULL);
            index = 0;
        }
        if (index < maxCount)
        {
            EventBase* base = (EventBase*) events[index].udata;
            if (!base) return NULL;
            base->dataLen = events[index].data;
            base->eventType = 0;
            if (events[index].flags & EV_ERROR)
            {
                base->eventType |= ERR_EVT;
            }
            switch (events[index].filter)
            {
                case EVFILT_READ:
                {
                    base->eventType |= IN_EVT;
                }break;
                case EVFILT_WRITE:
                {
                    base->eventType |= OUT_EVT;
                }break;
            }
            index++;
            return base;
        }
        return NULL;
    }
    Connection::Connection()
    {
        directDealCmd = true;
        allReadSize = 0;
    }

    /**
     * Connection 处理
     **/
    void Connection::destroy()
    {
        Target::destroy();
        ::close(socket);
        socket = -1;
    }

    /**
     * 发送消息
     */
    void Connection::sendCmd(void *cmd,unsigned int len)
    {
        Decoder  decoder;
        decoder.encode(cmd,len);
        sends.write(decoder.getRecord());
        if (evt)
            evt->startWrite();
    }
    /**
     * 从socket 读数据
     */
    int Connection::read(void *cmd,unsigned int len)
    {
        return ::recv(socket,cmd,len,0);
    }
    /**
     * 向socket 写数据
     */
    int Connection::send(void *cmd,unsigned int len)
    {
        if (socket == -1) return -1;
        return ::send(socket,cmd,len,0);
    }
    /**
     * 将消息接受到缓存
     **/
    unsigned int Connection::recv(void *cmd,unsigned int size)
    {
        unsigned int realcopy = 0;
        while (!recvs.empty())
        {
            Record *record = NULL;
            if (recvs.readOnly(record))
            {
                realcopy = record->recv(cmd,size);
                if (record->empty())
                {
                    delete record;
                    recvs.pop();
                }
                if (realcopy == size)
                {
                    return size;
                }
            }
        }
        return realcopy;
    }
    /**
     * 在pool 中处理接受
     **/
    void Connection::doRead(EventBase *evt,stGetPackage *callback)
    {
        Event<Connection>* event = static_cast<Event<Connection>*>( evt );
        while(true)
        {
            memset(buffer,0,EventBase::MAX_BUFFER_LEN);
            int leftLen = ::recv(socket,buffer,EventBase::MAX_BUFFER_LEN,0);
            allReadSize += leftLen;
            if (leftLen == -1)
            {
                // printf("---接受数据到头了 %d--\n",allReadSize);
                return;
            }
            if (leftLen == 0)
            {
                socket = -1;
                evt->eventType = ERR_EVT;
                return;
            }
            if (directDealCmd) // Ö±½Ó´¦ÀíÏûÏ¢
            {
                //printf("---接受并处理字节数:%d\n",leftLen);
                Record record(buffer,leftLen);
                decoder.decode(&record,callback);
            }
            else
            {
                Record *record = new Record(buffer,leftLen);
                //recvs.push_back(record);
                recvs.write(record);
            }
            if (leftLen <EventBase::MAX_BUFFER_LEN)
            {
                //              break;
            }
        }
    }
    
    /**
     * 在pool 中处理发送
     **/
    void Connection::doSend(EventBase *evt)
    {
        bool tag = false;
        Event<Connection>* event = static_cast<Event<Connection>*>( evt );
        event->stopWrite();
        while (!sends.empty())
        {
            Record *record = NULL;
            if (sends.readOnly(record))
            {
                if (record->sendOver(this))
                {
                    sends.pop();
                    delete record;
                }
                else
                {
                    tag = true;
                    break;
                }
            }else break;
        }
        if (tag)
        {
            evt->startWrite();
        }
        
    }
    void Connection::setnonblock(int socket)
    {
        int opts;
        opts=fcntl(socket,F_GETFL);
        if(opts<0)
        {
            return;
        }
        opts = opts|O_NONBLOCK;
        if(fcntl(socket,F_SETFL,opts)<0)
        {
            return;
        }
    }
    /**
     * 处理Client
     **/
    void Client::init(const char *ip,unsigned short port)
    {
        socket = ::socket(AF_INET,SOCK_STREAM,0);
        if(socket == -1)
        {
            // TODO error
        }
        struct sockaddr_in addrServer;

        memset(&addrServer,0,sizeof(sockaddr_in));
        addrServer.sin_family = AF_INET;
        addrServer.sin_addr.s_addr = inet_addr(ip);
        addrServer.sin_port = htons(port);
        
        if(connect(socket,(const struct sockaddr *)&addrServer,sizeof(sockaddr)) != 0)
        {
            // TODO error
            socket = -1;
        }
        setnonblock(socket);
    }
    void Client::close()
    {
        ::close(socket);
        socket = -1;
    }
    /**
     * 处理Server
     */
    void Server::init(const char *ip,unsigned short port)
    {
        struct sockaddr_in ServerAddress;
        
        socket = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        setnonblock(socket);
        int reuse = 1;
        setsockopt(socket,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
        
        memset((char *)&ServerAddress,0, sizeof(ServerAddress));
        ServerAddress.sin_family = AF_INET;
        ServerAddress.sin_addr.s_addr = inet_addr(ip);
        ServerAddress.sin_port = htons(port);
        
        bind(socket, (struct sockaddr *) &ServerAddress, sizeof(ServerAddress));
        
        listen(socket,4026);
    }
    void Server::setnonblock(int socket)
    {
        int opts;
        opts=fcntl(socket,F_GETFL);
        if(opts<0)
        {
            return;
        }
        opts = opts|O_NONBLOCK;
        if(fcntl(socket,F_SETFL,opts)<0)
        {
            return;
        }
    }
    int Server::getPeerHandle(){
        socklen_t clilen = 1024;
        struct sockaddr_in addr;
        int con = ::accept(socket,(struct sockaddr*)(&addr),&clilen);
        setnonblock(con);
        return con;
    }	
}
#endif