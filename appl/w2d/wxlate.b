Wi: ref Winst;

xwasmload(op: int)
{

}

wasm2dis(codes: array of ref Winst)
{
	for(i := 0; i < len codes; i++) {
		# if start of basic block
		#clearreg();
		Wi = codes[i];
		case Wi.opcode {
		Wglobal_get =>
			;
		Wi32_load =>
			;
		Wi32_store =>	
			;
		Wi32_const =>
			;
		}
	}
}

wxlate(m: ref Mod)
{
	for(i := 0; i < len m.codesection.codes; i++) {
		#openframe();
		#flowgraph();
		#simwasm();
		#unify();
		#wasm2dis(m.codesection.codes[i].code);
	}
}

