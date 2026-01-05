#0
	addw	72(fp),64(fp),80(fp)
	movw	80(fp),0(32(fp))
	ret	
	desc	$0,8,"80"
	desc	$1,88,""
	var	@mp,8
	module	Add
	link	1,0,0x6584767b,"add"
	ldts	@ldt,0
	source	"/home/caerwyn/github/inferno-w2d/appl/ex/add.b"
