package fatca;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import fatca.FATCAXmlSigner.SigRefIdPos;
import fatca.FATCAXmlSigner.SigXmlTransform;

/*
 * @author	Subir Paul (IT:ES:SE:PE)
 * 
 */
public class TestMain {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	private FATCAXmlSigner signer = null;
	private FATCAPackager pkger = null;

	// sender FFI or HCTA
	private String canadaGiin = "000000.00000.TA.124";
	private PrivateKey canadaSigKey = null;
	private X509Certificate canadaPubCert = null;
	
	// receiver
	private String usaGiin = "000000.00000.TA.840";
	private X509Certificate usaCert = null;
	private PrivateKey usaPrivateKey = null; 
	
	// approver - for model1 option2
	private String mexicoGiin = "000000.00000.TA.484";
	private X509Certificate mexicoPubCert = null;
	private PrivateKey mexicoPrivateKey = null; 
	
	public TestMain() throws Exception{
		signer = new FATCAXmlSigner();
		pkger = new FATCAPackager();
		canadaSigKey = UtilShared.getPrivateKey("jks", "Keystore/Canada_PrepTool/KSprivateCA.jks", "pwd123", "CAN2014", "CANADAcert");
		canadaPubCert = UtilShared.getCert("jks", "Keystore/Canada_PrepTool/KSpublicCA.jks", "pwd123", "CANADAcert");
		usaCert = UtilShared.getCert("jks", "Keystore/IRS_PrepTool/KSpublicUS.jks", "pwd123", "IRScert");
		mexicoPubCert = UtilShared.getCert("jks", "Keystore/Mexico_PrepTool/KSpublicMX.jks", "pwd123", "MEXICOcert");
		usaPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/IRS_PrepTool/KSprivateUS.jks", "pwd123", "password", "IRScert");
		mexicoPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/Mexico_PrepTool/KSprivateMX.jks", "pwd123", "MEX2014", "MEXICOcert");
	}
	
	public static void main(String[] args) throws Exception {
		String canadaXml = "000000.00000.TA.124_0_Payload.xml";
		String signedCanadaXml = canadaXml + ".signed";
		boolean signatureSuccess = true;
		
		TestMain m = new TestMain();
		
		m.signer.signXmlFileStreaming(canadaXml, signedCanadaXml, m.canadaSigKey, m.canadaPubCert);
		signatureSuccess = signatureSuccess & UtilShared.verifySignatureDOM(signedCanadaXml, m.canadaPubCert.getPublicKey());
		
		m.signer.signXmlFileStreaming(canadaXml, signedCanadaXml, m.canadaSigKey, m.canadaPubCert, SigRefIdPos.Object, SigXmlTransform.Inclusive);
		signatureSuccess = signatureSuccess & UtilShared.verifySignatureDOM(signedCanadaXml, m.canadaPubCert.getPublicKey());
		
		m.signer.signXmlFileStreaming(canadaXml, signedCanadaXml, m.canadaSigKey, m.canadaPubCert, SigRefIdPos.Object, SigXmlTransform.Exclusive);
		signatureSuccess = signatureSuccess & UtilShared.verifySignatureDOM(signedCanadaXml, m.canadaPubCert.getPublicKey());
		
		//DOM based signature
		m.signer.signXmlFile(canadaXml, signedCanadaXml, m.canadaSigKey, m.canadaPubCert);
		signatureSuccess = signatureSuccess & UtilShared.verifySignatureDOM(signedCanadaXml, m.canadaPubCert.getPublicKey());
		
		m.signer.signXmlFile(canadaXml, signedCanadaXml, m.canadaSigKey, m.canadaPubCert, SigRefIdPos.Object, SigXmlTransform.Inclusive);
		signatureSuccess = signatureSuccess & UtilShared.verifySignatureDOM(signedCanadaXml, m.canadaPubCert.getPublicKey());
		
		m.signer.signXmlFile(canadaXml, signedCanadaXml, m.canadaSigKey, m.canadaPubCert, SigRefIdPos.Object, SigXmlTransform.Exclusive);
		signatureSuccess = signatureSuccess & UtilShared.verifySignatureDOM(signedCanadaXml, m.canadaPubCert.getPublicKey());

		String idesOutFile = m.pkger.createPkg(signedCanadaXml, m.canadaGiin, m.usaGiin, m.usaCert, 2014);
		logger.debug(idesOutFile);

		m.pkger.unpack(idesOutFile, m.usaPrivateKey);
		
		idesOutFile = m.pkger.createPkgWithApprover(signedCanadaXml, m.canadaGiin, m.usaGiin, m.usaCert, m.mexicoGiin, m.mexicoPubCert, 2014);
		logger.debug(idesOutFile);

		m.pkger.unpackForApprover(idesOutFile, m.mexicoPrivateKey);
		
		idesOutFile = m.pkger.signAndCreatePkgStreaming(canadaXml, m.canadaSigKey, m.canadaPubCert, m.canadaGiin, m.usaGiin, m.usaCert, 2014);
		logger.debug(idesOutFile);

		m.pkger.unpack(idesOutFile, m.usaPrivateKey);
		
		idesOutFile = m.pkger.signAndCreatePkgWithApprover(canadaXml, m.canadaSigKey, m.canadaPubCert, m.canadaGiin, m.usaGiin, m.usaCert, m.mexicoGiin, m.mexicoPubCert, 2014);
		logger.debug(idesOutFile);
	
		m.pkger.unpackForApprover(idesOutFile, m.mexicoPrivateKey);

		logger.info("signatureSuccess=" + signatureSuccess);
	}
}
