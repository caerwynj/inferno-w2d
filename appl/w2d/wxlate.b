
xwasmload(op: int)
{

}

wasm2dis(codes: array of ref Winst)
{
	for(i := 0; i < len codes; i++) {
		w := codes[i];
		case w.opcode {
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
		clearreg();
		wasm2dis(m.codesection.codes[i].code);
	}
}

