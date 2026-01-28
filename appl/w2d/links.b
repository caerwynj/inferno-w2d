#
# Manage .dis Link Section.
#

Link: adt {
	id:	int;		# dis type identifier
	pc:	int;		# method entry pc
	sig:	int;		# MD5 signature
	name:	string;		# method name
	next:	cyclic ref Link;
};

links:	ref Link;
last:	ref Link;
nlinks:	int;

#
# Create a Link entry; one for each function defined in the module.
#

xtrnlink(id: int, pc: int, isig: int, name: string, sig: string)
{
	l: ref Link;

	l = ref Link(id, pc, isig, name + sig, nil);
	if(name == "main")
		setentry(pc, id);
	if(links == nil)
		links = l;
	else
		last.next = l;
	last = l;
	nlinks += 1;
}

#
# Emit assembly 'link' directives.
#

asmlinks()
{
	l: ref Link;

	for(l = links; l != nil; l = l.next) {
		bout.puts("\tlink\t" + string l.id + "," + string l.pc
			+ ",0x" + hex(l.sig, 0) + ",\"" + l.name + "\"\n");
	}
}

sbllinks(bsym: ref Bufio->Iobuf)
{
	l: ref Link;

	bsym.puts(string nlinks + "\n");
	for(l = links; l != nil; l = l.next) {
		bsym.puts(string l.pc + ":" + l.name + "\n");
		bsym.puts("0\n");    # args
		bsym.puts("0\n");    # locals
		bsym.puts("n\n");    # return type
	}
}

disnlinks()
{
	discon(nlinks);
}

dislinks()
{
	l: ref Link;

	for(l = links; l != nil; l = l.next) {
		discon(l.pc);
		discon(l.id);
		disword(l.sig);
		bout.puts(l.name);
		bout.putb(byte 0);
	}
}
