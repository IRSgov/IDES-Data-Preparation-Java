package fatca.test;

import fatca.impl.FATCAPackager;
import fatca.intf.IFATCAPackager;
import fatca.metadata.FATCAMetadata;
import impl.SignatureVerifier;
import impl.Signer;
import intf.IMetadata;
import intf.ISignatureVerifier;
import intf.ISigner;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import util.UtilShared;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class FATCATestMain {
	protected static Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	private IFATCAPackager pkger = new FATCAPackager();
	private ISigner signer = new Signer();
	private ISignatureVerifier signetureVerifier = new SignatureVerifier();
	private IMetadata metadata = new FATCAMetadata();
	
	// sender
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
	
	public FATCATestMain() throws Exception {
		pkger.setSigner(signer);
		pkger.setMetadata(metadata);
		signer.setSignatureVerifier(signetureVerifier);
		myPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/Canada_PrepTool/KSprivateCA.jks", "pwd123", "CAN2014", "CANADAcert");
		myPublicCert = UtilShared.getCert("jks", "Keystore/Canada_PrepTool/KSpublicCA.jks", "pwd123", "CANADAcert");
		usaCert = UtilShared.getCert("jks", "Keystore/IRS_PrepTool/KSpublicUS.jks", "pwd123", "IRScert");
		approverPublicCert = UtilShared.getCert("jks", "Keystore/Mexico_PrepTool/KSpublicMX.jks", "pwd123", "MEXICOcert");
		usaPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/IRS_PrepTool/KSprivateUS.jks", "pwd123", "password", "IRScert");
		approverPrivateKey = UtilShared.getPrivateKey("jks", "Keystore/Mexico_PrepTool/KSprivateMX.jks", "pwd123", "MEX2014", "MEXICOcert");
	}
	
	public static void main(String[] args) throws Exception {
		LogManager.getRootLogger().setLevel(Level.DEBUG);
		String signedXml = "Sample.000000.00000.TA.124_Payload.signed.xml";
		String myXml = "Sample.000000.00000.TA.124_Payload.xml";
		String myPdf = "Sample.pdf";
		String myText = "Sample.txt";
		int taxyear = 2017;
		
		FATCATestMain m = new FATCATestMain();
		
		String fatcaEntCommTypeCd = "RPT";
		
		m.signer.setProperty("verifyAllSignature", true);
		
		String idesPkg = m.pkger.signAndCreatePkgStreaming(myXml, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, taxyear, fatcaEntCommTypeCd);
		logger.debug(idesPkg);
		
		m.pkger.unpack(idesPkg, m.usaPrivateKey);
		
		//binary/text file pkg
		fatcaEntCommTypeCd = "CAR";
		String fileFormatCd = "PDF";
		idesPkg = m.pkger.signBinaryFileAndCreatePkgStreaming(myPdf, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, 
				taxyear, fileFormatCd, fatcaEntCommTypeCd);

		idesPkg = m.pkger.signTextFileAndCreatePkgStreaming(myText, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, 
				taxyear, fatcaEntCommTypeCd);

		//model1 option2
		fatcaEntCommTypeCd = "RPT";
		idesPkg = m.pkger.signAndCreatePkgWithApproverStreaming(myXml, m.myPrivateKey, m.myPublicCert, m.myGiin, m.usaGiin, m.usaCert, m.approverGiin, 
				m.approverPublicCert, taxyear, fatcaEntCommTypeCd);
		logger.debug(idesPkg);
	
		m.pkger.unpackForApprover(idesPkg, m.approverPrivateKey);
		
		m.signetureVerifier.verifySignature(signedXml, m.myPublicCert);
	}
}
