#0
	movw	72(fp),80(fp)
	movw	64(fp),88(fp)
	addw	80(fp),88(fp),80(fp)
	movw	80(fp),0(32(fp))
	ret	
	entry	0, 0
	desc	$0,0,""
	desc	$1,96,"0000"
	var	@mp,0
	module	Wasm
	link	1,0,0x6584767b,"func0"
