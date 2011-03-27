// SetLinkerVersion.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <sstream>


using namespace std;

class SSException : public exception
{
public:
    SSException(const char * pcszError) : m_sError(pcszError) {}
    virtual const char * what() const throw() { return m_sError.c_str(); }

private:
    string m_sError;

};

bool SetLinkerVersion(HANDLE hFile, int nMajor, int nMinor, DWORD dwBinaryType)
{
    HANDLE hFileMap = INVALID_HANDLE_VALUE;
    LPVOID lpFileBase = 0;

    try {
        hFileMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
        if(hFileMap == 0)
            throw(SSException("Could not open file mapping"));

        lpFileBase = MapViewOfFile(hFileMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if(lpFileBase == 0)
            throw(SSException("Could not map view of file"));

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
        if(dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            throw(SSException("File does not look like an EXE or DLL"));

        if(dwBinaryType == 32) {
            PIMAGE_NT_HEADERS32 pImageNtHeader =
                (PIMAGE_NT_HEADERS32)((char*) dosHeader + dosHeader->e_lfanew);
            char * peSig = (char *) &pImageNtHeader->Signature;
            if(!(peSig[0] == 'P' && peSig[1] == 'E' && peSig[2] == 0 && peSig[3] == 0))
                throw(SSException("PE signature is incorrect"));
            pImageNtHeader->OptionalHeader.MajorLinkerVersion = nMajor;
            pImageNtHeader->OptionalHeader.MinorLinkerVersion = nMinor;            
        } else if(dwBinaryType == 32) {
            PIMAGE_NT_HEADERS64 pImageNtHeader =
                (PIMAGE_NT_HEADERS64)((char*) dosHeader + dosHeader->e_lfanew);
            char * peSig = (char *) &pImageNtHeader->Signature;
            if(!(peSig[0] == 'P' && peSig[1] == 'E' && peSig[2] == 0 && peSig[3] == 0))
                throw(SSException("PE signature is incorrect"));
            pImageNtHeader->OptionalHeader.MajorLinkerVersion = nMajor;
            pImageNtHeader->OptionalHeader.MinorLinkerVersion = nMinor;            
        } else {
            throw(SSException("Binary type must be 32 or 64"));
        }
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMap);
        return true;
    }
    catch(SSException & e)
    {
        UnmapViewOfFile(lpFileBase);
        CloseHandle(hFileMap);
        throw(e);
    }
}

void ShowHelp(void)
{
    cout << "Usage is -M <majorLinkerVersion> -m <minorLinkerVersion> [<-32> | <-64>] -f <file>" << endl;
    cout << "   -M   Major linker version" << endl;
    cout << "   -m   Minor linker version" << endl;
    cout << "   -32  Input file is 32 bit." << endl;
    cout << "   -64  Input file is 64 bit." << endl;
    cout << "   -f   Input file, EXE or DLL" << endl;
}

int main(int argc, char * argv[])
{
    cout << sizeof(IMAGE_DOS_HEADER) << endl;
    cout << sizeof(WORD) << endl;
    exit(0);
    if(argc < 5) {
        ShowHelp();
        return 1; 
    }

    string sInFile;
    int nMajorVersion, nMinorVersion;
    DWORD dwBinaryType;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    try {
        for(int i = 1; i < argc; ++i) {
            if(i + 1 != argc) {
                string sArg(argv[i]);
                if(sArg == "-f")
                    sInFile = argv[i++ + 1];
                else if(sArg == "-M")
                    nMajorVersion = atoi(argv[i++ + 1]);
                else if(sArg == "-m")
                    nMinorVersion = atoi(argv[i++ + 1]);
                else if(sArg == "-32" || sArg == "-64")
                    dwBinaryType = abs(atoi(sArg.c_str()));
                else {
                    stringstream ss;
                    ss << "Invalid argument supplied \"" << sArg << "\"";
                    throw(SSException(ss.str().c_str()));
                }
            }
        }

        hFile = CreateFile(sInFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
        if(hFile == INVALID_HANDLE_VALUE) {
            stringstream ss;
            ss << "Problem reading file " << sInFile;
            throw(SSException(ss.str().c_str()));
        }

        FILETIME creationTime, fileTime, lastWriteTime;
        if(GetFileTime(hFile, &creationTime, &fileTime, &lastWriteTime) == 0) {
            throw(SSException("Error retrieving file time info"));
        }
        CloseHandle(hFile);

        hFile = CreateFile(sInFile.c_str(), GENERIC_WRITE | GENERIC_READ,
                           0 /*FILE_SHARE_WRITE*/, NULL, OPEN_EXISTING,
                           0, NULL);
        if(hFile == INVALID_HANDLE_VALUE) {
            throw(SSException("Problem opening file for write"));
        }

        if(SetLinkerVersion(hFile, nMajorVersion, nMinorVersion, dwBinaryType) == 0)
            throw(SSException("Error setting linker version"));
        if(SetFileTime(hFile, &creationTime, &fileTime, &lastWriteTime) == 0)
            throw(SSException("Error setting file time"));
        CloseHandle(hFile);

        return 0;

    }
    catch(const SSException & e)
    {        
        CloseHandle(hFile);
        cout << "* * * * *  ERROR  * * * * *" << endl;
        cout << e.what() << endl;
        return 1;
    }

}
