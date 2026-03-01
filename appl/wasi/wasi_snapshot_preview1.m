Wasi_snapshot_preview1: module
{
	setmem:    fn(mem: array of byte);
	proc_exit: fn(status: int);
	fd_write:  fn(fd: int, iovs: int, iovs_len: int, nwritten: int): int;
	fd_close:  fn(fd: int): int;
	fd_seek:   fn(fd: int, offset: big, whence: int, newoffset: int): int;
};
