public class MTU {

	public static void main(String[] args) {
		Parser parser =  new Parser();
		System.out.println("Parser created");

		byte[] cryptA = parser.encryptTOTP("rtu_a", "Teste mais compridao");
		byte[] cryptB = parser.encryptTOTP("rtu_b", "Teste");

		parser.decryptTOTP("rtu_a", cryptA);
		parser.decryptTOTP("rtu_b", cryptB);
	}

}
