package intf;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public interface ISignerNonXml {
	//wraps text file in <Wrapper> xml tag and sign
    public boolean wrapTextFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    public boolean wrapTextFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
	
	//wraps base64 encoded binary content in <Wrapper> xml tag and sign
    public boolean wrapBinaryFileInXmlAndSign(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    public boolean wrapBinaryFileInXmlAndSignStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;

	//not used in this packaging. Sign a text file with no transformation - DOM based signing
    public boolean signTextFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
	//not used in this packaging. Sign a text file with no transformation - DOM based signing
    public boolean signTextFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    //not used in this packaging. Sign a binary file with BINARY transformation - DOM based signing
    public boolean signBinaryFile(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
    //not used in this packaging. Sign a binary file with BINARY transformation - streaming based signing
    public boolean signBinaryFileStreaming(String infile, String outfile, PrivateKey sigkey, X509Certificate sugPubCert) throws Exception;
}
