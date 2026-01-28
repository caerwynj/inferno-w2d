#
# Dis instruction allocation.
#

pcdis:		int;
THISCLASS:	string;

#
# Allocate a Dis instruction.
#

newi(op: int): ref Inst
{
	i: ref Inst;

	i = ref Inst(byte op, nil, nil, nil, pcdis, 0, nil);
	i.s = ref Addr(byte 0, 0, 0);
	i.m = ref Addr(byte 0, 0, 0);
	i.d = ref Addr(byte 0, 0, 0);
	pcdis += 1;
	if(ihead == nil)
		ihead = i;
	if(itail != nil)
		itail.next = i;
	itail = i;
	return i;
}
