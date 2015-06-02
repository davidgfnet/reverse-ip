
#ifndef GZBUFFER_H__
#define GZBUFFER_H__ 1

#include <string>
#include <string.h>

class mgzbuffer {
public:
	mgzbuffer(FILE * fd, unsigned int size) : fd(fd), fileoffset(0), fsize(size), bufStart(0), bufAvail(0) {
		infstream.zalloc = Z_NULL;
		infstream.zfree = Z_NULL;
		infstream.opaque = Z_NULL;

		infstream.avail_in = Z_NULL;
		infstream.next_in = Z_NULL;
		infstream.avail_out = Z_NULL;
		infstream.next_out = Z_NULL;

		inflateInit2(&infstream, 16+MAX_WBITS);

		fillBuffer();
	}

	~mgzbuffer() {
		inflateEnd(&infstream);
	}

	void fillBuffer() {
		// Quick quit
		if (fileoffset == fsize) return;

		// Move existing data if necessary
		if (bufStart != 0) {
			memmove(&buffer[0], &buffer[bufStart], bufAvail);
			bufStart = 0;
		}

		while (bufAvail < bufSize && fileoffset < fsize) {
			char tempbuf[64*1024];
			int rem = fsize - fileoffset;
			int toread = (rem > sizeof(tempbuf)) ? sizeof(tempbuf) : rem;

			toread = fread(tempbuf, 1, toread, fd);
			if (toread < 0) { // Error!
				fileoffset = fsize;
				return;
			}
			fseek(fd, -toread, SEEK_CUR);

			infstream.avail_in = toread;
			infstream.next_in = (Bytef*)&tempbuf[0];
			infstream.avail_out = (uInt)(bufSize - bufAvail);
			infstream.next_out = (Bytef*)&buffer[bufAvail];

			int rc = inflate(&infstream, Z_FINISH);
			int input_read = toread - infstream.avail_in;
			int output_written = (bufSize - bufAvail) - infstream.avail_out;
			
			fseek(fd, input_read, SEEK_CUR);
			bufAvail += output_written;
			fileoffset += input_read;
		}
	}

	bool getc(char * c) {
		if (bufAvail == 0)
			return false;

		*c = buffer[bufStart];
		bufStart++;
		bufAvail--;

		if (bufAvail < bufSize/2)
			fillBuffer();

		return true;
	}

	bool getString(std::string & s) {
		int end = -1;
		for (int s = bufStart; s < bufStart + bufAvail; s++) {
			if (buffer[s] == 0) {
				end = s;
				break;
			}
		}
		if (end < 0)
			return false;

		s = std::string(&buffer[bufStart]);
		bufStart += (s.size()+1);
		bufAvail -= (s.size()+1);

		if (bufAvail < bufSize/2)
			fillBuffer();

		return true;
	}
	

private:
	FILE * fd;
	int fileoffset;
	unsigned int fsize;
	z_stream infstream;

	static const unsigned int bufSize = 128*1024;
	char buffer[bufSize];
	int bufStart;
	int bufAvail;
};

#endif // GZBUFFER_H


