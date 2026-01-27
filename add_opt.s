#0
	movw	40(fp),48(fp)
	movw	32(fp),56(fp)
	addw	48(fp),56(fp),48(fp)
	movw	48(fp),32(fp)
	ret	
	entry	0, 0
	desc	$0,0,""
	var	@mp,0
	module	Wasm
	link	1,0,0x4a617661,"func0"
