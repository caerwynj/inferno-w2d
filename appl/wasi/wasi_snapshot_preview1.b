implement Wasi_snapshot_preview1;

include "sys.m";
	sys: Sys;

include "wasi_snapshot_preview1.m";

mem: array of byte;

setmem(m: array of byte)
{
	mem = m;
}

i32get(buf: array of byte, off: int): int
{
	return int buf[off]
		| (int buf[off+1] << 8)
		| (int buf[off+2] << 16)
		| (int buf[off+3] << 24);
}

i32put(buf: array of byte, off: int, v: int)
{
	buf[off] = byte v;
	buf[off+1] = byte (v >> 8);
	buf[off+2] = byte (v >> 16);
	buf[off+3] = byte (v >> 24);
}

proc_exit(status: int)
{
	if(sys == nil)
		sys = load Sys Sys->PATH;
	sys->print("exit %d\n", status);
	exit;
}

fd_write(fd: int, iovs: int, iovs_len: int, nwritten: int): int
{
	if(sys == nil)
		sys = load Sys Sys->PATH;

	total := 0;
	for(i := 0; i < iovs_len; i++) {
		ptr := i32get(mem, iovs + i*8);
		ln := i32get(mem, iovs + i*8 + 4);
		if(ln > 0) {
			buf := mem[ptr:ptr+ln];
			sys->write(sys->fildes(fd), buf, ln);
			total += ln;
		}
	}

	i32put(mem, nwritten, total);
	return 0;
}

fd_close(fd: int): int
{
	return 0;
}

fd_seek(fd: int, offset: big, whence: int, newoffset: int): int
{
	return 8;  # ERRNO_NOSYS
}
