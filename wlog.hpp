#ifndef WLOG_H_
#define WLOG_H_
#ifdef __linux__
#include <pwd.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#define gettid() syscall(__NR_gettid)
#define PATH_SPERATE '/'
#elif defined(WIN32)
#include <direct.h>
#include <io.h>
#include <windows.h>
#define PATH_SPERATE '\\'
#define gettid() GetCurrentThreadId()
#define mkdir(x,y)	_mkdir(x)
#define NAME_MAX            255
#define PATH_MAX            512
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2
#endif

#include <exception>
#include <iostream>
#include <string>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <limits.h>
#include <sys/stat.h>

struct LogHelper
{
	LogHelper(int xlevel,int xline, const char *xfile, const char *xfunction)
	:level(xlevel),line(xline),file(xfile),function(xfunction) {}
	int level;
	int line;
	const char *file;
	const char *function;
};

#define WLOG_MUCH	__LINE__,__FILE__,__FUNCTION__

#define	WLOG_EMERG	 LogHelper(0,WLOG_MUCH)
#define	WLOG_ALERT	 LogHelper(1,WLOG_MUCH)
#define	WLOG_CRIT	 LogHelper(2,WLOG_MUCH)
#define	WLOG_ERR	 LogHelper(3,WLOG_MUCH)
#define	WLOG_WARNING LogHelper(4,WLOG_MUCH)
#define	WLOG_NOTICE	 LogHelper(5,WLOG_MUCH)
#define	WLOG_INFO	 LogHelper(6,WLOG_MUCH)
#define	WLOG_DEBUG	 LogHelper(7,WLOG_MUCH)

#define LOG_MAX_SIZE	100	//10M
#define LOG_NUM_KEEP	5

#define LT_FILE		0x01
#define LT_TERMINAL 0x02
#define LT_BOTH		(LT_FILE | LT_TERMINAL)

#define DEFAULT_LOG_DIR	"./"
#define DEFAULT_LOG_TYPE LT_FILE

#ifdef WIN32
inline static int gettimeofday(struct timeval *tv, void* tz)
{
#define EPOCHFILETIME (116444736000000000ULL)
  FILETIME ft;
  LARGE_INTEGER li;
  unsigned long long tt;

  GetSystemTimeAsFileTime(&ft);
  li.LowPart = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;
  tt = (li.QuadPart - EPOCHFILETIME) / 10;
  tv->tv_sec = time((time_t*)&(tv->tv_sec));//tt / 1000000;
  tv->tv_usec = tt % 1000000;

  return 0;
}

#define localtime_r(x,y)	localtime_s(y,x)
#define snprintf	sprintf_s
#endif


class WLock
{
public:
	WLock()
	{
#ifdef __linux
		//设置锁的互斥类型，为了支持在一个线程内部多次调用lock操作而不阻塞
		//缺省为PTHREAD_MUTEX_NORMAL ,我们把其设置为PTHREAD_MUTEX_RECURSIVE
		pthread_mutexattr_t attr;
		pthread_mutexattr_init (&attr);
		pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&m_mutex,&attr);
		pthread_mutexattr_destroy (&attr);
#elif defined(WIN32)
		::InitializeCriticalSection( &m_CriticalSection );
#endif
	}

	~WLock()
	{
#ifdef __linux__
		pthread_mutex_destroy( &m_mutex );
#elif defined(WIN32)
		::DeleteCriticalSection( &m_CriticalSection );
#endif
	}

	void Lock()
	{
#ifdef __linux__
		pthread_mutex_lock( &m_mutex );
#elif defined(WIN32)
		::EnterCriticalSection( &m_CriticalSection );
#endif
	}

	void Unlock()
	{
#ifdef __linux
		pthread_mutex_unlock( &m_mutex );
#elif defined(WIN32)
		::LeaveCriticalSection( &m_CriticalSection );
#endif
	}

private:
#ifdef __linux
	pthread_mutex_t  m_mutex;
#elif defined(WIN32)
	CRITICAL_SECTION m_CriticalSection;
#endif
};


class WLog
{
public:
	//日志输出方式，只有屏幕
	explicit WLog(int logLevel = 6)
	{
		logtype = LT_TERMINAL;
		logfd = 0;
		level = logLevel;
		currLength = 0;
		capacity = INT_MAX;
		return;
	}
	//日志输出方式，isBoth = false写文件，isBoth = true屏幕文件都有
	explicit WLog(const char* logfile, bool isBoth = false, int logLevel = 6,
			int maxsize = LOG_MAX_SIZE, const char *maindir = DEFAULT_LOG_DIR)
	{
		level = logLevel;
		if(isBoth)
			logtype = LT_BOTH;
		else
			logtype = LT_FILE;
		mkdir(maindir,0755);
		if(maxsize <= 0)
			maxsize = 1;
		capacity = maxsize*1024*1024;

		if(logfile == NULL || logfile[0] == 0)
			strncpy(fileName,GetModuleFileName().c_str(),sizeof(fileName) - 5);
		else
			strncpy(fileName,logfile,sizeof(fileName) - 5);
		strcat(fileName,".log");

		if(maindir == NULL || maindir[0] == 0)
			strcpy(filePath,"");
		else
			strncpy(filePath, maindir, sizeof(filePath) - strlen(fileName) - 1);

		if(strlen(filePath) > 0 && filePath[strlen(filePath)-1] != PATH_SPERATE)
		{
			char p[2] = {PATH_SPERATE,0};
			strcat(filePath,p);
		}
		strcat(filePath,fileName);

		logfd = open(filePath,O_WRONLY|O_CREAT|O_APPEND,0640);
		if(logfd <= 0)
		{
			std::cerr<<"Can't open "<<filePath<<std::endl;
			throw std::exception();
		}

		struct stat buf;
		if(stat(filePath,&buf) == 0)
		{
			currLength = buf.st_size;
		}
		else
		{
			std::cerr<<"Can't stat "<<filePath<<std::endl;
			throw std::exception();
		}

		if(currLength > capacity)
			ChangeFile();
		LogCreateInfo();
	}

	~WLog()
	{
		if(logfd)
			close(logfd);
	}

	void Log(const LogHelper &lh, const char *message,...)
	{
		va_list ap;
		va_start(ap,message);
		VLog(lh,message,ap);
		va_end(ap);
	}

	void VLog(const LogHelper &lh, const char *message,va_list ap)
	{
		if(lh.level > level)
			return;
		char sprint_buf[1024] = {0};
		vsnprintf(sprint_buf, sizeof(sprint_buf)-1, message, ap);

		struct timeval tv;
		gettimeofday(&tv, NULL);
		struct tm curt;
		time_t time = tv.tv_sec;
		localtime_r(&time,&curt);
		char *fileName;
		char pfile[256];
		strncpy(pfile, lh.file, sizeof(pfile));
		if((fileName = strrchr(const_cast<char*>(lh.file),PATH_SPERATE)) != NULL)
			fileName++;
		else
			fileName = pfile;

		const char logLevelStr[][16] = {"Emergency","Alert","Critical","Error","Warning","Notice","Info","Debug"};
		char printf_buf[1024];
		int len = snprintf(printf_buf, sizeof(printf_buf)-1, "%02d-%02d %02d:%02d:%02d.%06ld][%s][%s-%d][%ld]%s",
				curt.tm_mon+1,curt.tm_mday,curt.tm_hour,curt.tm_min,curt.tm_sec,tv.tv_usec,
				logLevelStr[lh.level], lh.function, lh.line, gettid(),sprint_buf);
		if(printf_buf[len - 1] != '\n')
		{
			printf_buf[len++] = '\n';
			printf_buf[len] = '\0';
		}

		if(logtype & LT_FILE)
			LogWrite(printf_buf,len);
		if(logtype & LT_TERMINAL)
			write(STDOUT_FILENO,printf_buf,len);
	}
private:
	WLog(const WLog &log);
	WLog& operator=(const WLog &log);

	void ChangeFile()
	{
		close(logfd);
		int keep = LOG_NUM_KEEP;
		char newfile[PATH_MAX],oldfile[PATH_MAX];
		while(--keep)
		{
			snprintf(oldfile,sizeof(oldfile),"%s.%d",filePath,keep);
			snprintf(newfile,sizeof(newfile),"%s.%d",filePath,keep + 1);
			if(access(oldfile,0) == 0)
			{
				rename(oldfile,newfile);
			}
		}
		snprintf(newfile,sizeof(newfile),"%s.1",filePath);
		if(access(filePath,0) == 0)
		{
			rename(filePath,newfile);
		}
		logfd = open(filePath,O_WRONLY|O_CREAT|O_APPEND,0640);
		if(logfd <= 0)
		{
			std::cerr<<"Can't open "<<filePath<<std::endl;
			throw std::exception();
		}
		currLength = 0;
	}

	int LogWrite(const char *logStr,size_t len)
	{
		m_lock.Lock();
		currLength += len;
		if(currLength > capacity)
		{
			ChangeFile();//length has changed
			currLength += len;
		}
		if(write(logfd,logStr,len) != len)
		{
			perror("Can't write log !!! \n");
		}
		m_lock.Unlock();
		return 0;
	}

	void LogCreateInfo()
	{
		char createMessage[1024];
		time_t tm = time(&tm);
		struct tm date;
		localtime_r(&tm,&date);
		size_t len = sprintf(createMessage,
				"=============================================================\n"
				"\tCreate in %04d-%02d-%02d %02d:%02d:%02d by %s(%s)\n"
				"=============================================================\n",
				date.tm_year + 1900, date.tm_mon + 1, date.tm_mday,date.tm_hour,date.tm_min,date.tm_sec,
				GetModuleFileName().c_str(), GetCurrentUser().c_str());
		write(logfd,createMessage,len);
	}

private:
	std::string GetModuleFileName()
	{
#ifdef __linux__
		char path[128];
		sprintf(path,"/proc/%d/exe",getpid());

		char moduleFileName[1024];
		int readsize = readlink(path, moduleFileName, sizeof(moduleFileName));
		if (readsize == -1) {
			return NULL;
		}
		else
		{
			moduleFileName[readsize] = '\0';
			char *p;
			if((p = strrchr(moduleFileName,'/')) != NULL)
			{
				return p + 1;
			}
			else
				return moduleFileName;
		}
#elif defined(WIN32)
		TCHAR szPath[MAX_PATH];
		::GetModuleFileName(NULL,szPath,MAX_PATH);
		char pBuf[MAX_PATH];
		::WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,szPath,wcslen(szPath)+1,pBuf,MAX_PATH,NULL,NULL);
		char *p = strrchr(pBuf,'\\');
		if(p)
			return p+1;
		else
			return (char*)pBuf;
#endif
	}

	std::string GetCurrentUser()
	{
#ifdef __linux__
		struct passwd *pwd;
		pwd = getpwuid(getuid());
		return pwd->pw_name;
#elif defined(WIN32)
		TCHAR szPath[MAX_PATH];
		DWORD size=MAX_PATH;
		::GetUserName(szPath,(LPDWORD)&size);
		char pBuf[MAX_PATH];
		::WideCharToMultiByte(CP_ACP,WC_COMPOSITECHECK,szPath,wcslen(szPath)+1,pBuf,MAX_PATH,NULL,NULL);
		return (char*)pBuf;
#endif
	}


private:
	int level;
	int logtype;
	WLock m_lock;
	int logfd;
	uint64_t currLength;
	uint64_t capacity;
	char filePath[PATH_MAX];
	char fileName[NAME_MAX];
};

inline void logToDefault(const LogHelper &lh, const char *message,...)
{
	static WLog *pLog = new WLog("default");

	va_list ap;
	va_start(ap,message);
	pLog->VLog(lh, message,ap);
	va_end(ap);
}

#endif /* WLOG_H_ */
