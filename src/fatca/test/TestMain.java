package fatca.test;

import fatca.impl.FATCAPackager;
import fatca.intf.IPackager;
import fatca.intf.IPackager.MetadataFileFormat;
import fatca.util.UtilShared;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public class TestMain {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	private IPackager pkger = new FATCAPackager();
	//private ISigner signer = pkger.getSigner();

	// sender FFI or HCTA
	private String myGiin = "000000.00000.TA.124";
	private PrivateKey myPrivateKey = null;
	private X509Certificate myPublicCert = null;
	
	// receiver
	private String usaGiin = "000000.00000.TA.840";
	private X509Certificate usaCert = null;
	private PrivateKey usaPrivateKey = null; 
	
	// approver - for model1 option2
	private String approverGiin = "000000.00000.TA.484";
	private X509Certificate approverPublicCert = null;
	private PrivateKey approverPrivateKey = null; 
	
	public TestMain() throws Exception{
		myPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/Canada_PrepTool/KSprivateCA.jks", "pwd123", "CAN2014", "CANADAcert");
		myPublicCert = UtilShared.getCert("jks", "Keystore/Canada_PrepTool/KSpublicCA.jks", "pwd123", "CANADAcert");
		usaCert = UtilShared.getCert("jks", "Keystore/IRS_PrepTool/KSpublicUS.jks", "pwd123", "IRScert");
		approverPublicCert = UtilShared.getCert("jks", "Keystore/Mexico_PrepTool/KSpublicMX.jks", "pwd123", "MEXICOcert");
		usaPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/IRS_PrepTool/KSprivateUS.jks", "pwd123", "password", "IRScert");
		approverPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/Mexico_PrepTool/KSprivateMX.jks", "pwd123", "MEX2014", "MEXICOcert");
	}
	
	public static void main(String[] args) throws Exception {
		String myXml = "Sample.000000.00000.TA.124_Payload.xml";
		String myPdf = "Sample.pdf";
		String myText = "Sample.txt";
		int taxyear = 2015;
		//String signedCanadaXml = canadaXml + ".signed";
		
		TestMain m = new TestMain();
		
		//m.usaCert = (X509Certificate)UtilShared.getCert("Certs/encryption-service-nonprod_services_irs_gov.cer");
		
		String idesPkg = m.pkger.signAndCreatePkgStreaming(myXml, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, taxyear);
		logger.debug(idesPkg);
		
		m.pkger.unpack(idesPkg, m.usaPrivateKey);
		
		//binary/text file pkg
		idesPkg = m.pkger.signBinaryFileAndCreatePkgStreaming(myPdf, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, 
				taxyear, MetadataFileFormat.PDF);

		idesPkg = m.pkger.signTextFileAndCreatePkgStreaming(myText, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, taxyear);

		//model1 option2
		idesPkg = m.pkger.signAndCreatePkgWithApproverStreaming(myXml, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, m.approverGiin, m.approverPublicCert, 2014);
		logger.debug(idesPkg);
	
		m.pkger.unpackForApprover(idesPkg, m.approverPrivateKey);
	}
}
