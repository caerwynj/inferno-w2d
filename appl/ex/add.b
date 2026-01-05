implement Add;
include "sys.m";
include "draw.m";

Add: module { add: fn(a, b: int): int; };

add(a, b: int): int
{
	c: int;
	c = a + b;
	return c;
}
