package fatca.main;

import fatca.impl.FATCAPackager;
import fatca.intf.IFATCAPackager;
import fatca.metadata.FATCAMetadata;
import impl.SignatureVerifier;
import impl.Signer;
import intf.IMetadata;
import intf.ISignatureVerifier;
import intf.ISigner;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import util.UtilShared;

/*
 * @author	Subir Paul (OS:IT:ES:EST:PA:S1)
 * 
 */
public class FATCADataPrepTool {
	protected Logger logger = Logger.getLogger(new Object(){}.getClass().getEnclosingClass().getName());

	protected X509Certificate receiverPublicCert = null, senderPublicCert = null, approverPublicCert = null;
	protected PrivateKey receiverPrivateKey = null, senderPrivateKey = null, approverPrivateKey = null;
	
	protected String senderGiin = null, receiverGiin = null, approverGiin = null, 
			xmlSchema = null, xmlStartElemForSchemaValidation = null;
	protected int taxyear = -1;
	boolean isVerifyAllSignature = false, isValidateAllXMLSchema = false;
	
	protected IFATCAPackager pkgr = new FATCAPackager();
	protected ISigner signer = new Signer();
	protected ISignatureVerifier signatureVerifier = new SignatureVerifier();
	protected IMetadata metadata = new FATCAMetadata();
	
	protected String defaultConfigFile = "ConfigAndCmds.txt";
	
	public FATCADataPrepTool() {
		signer.setSignatureVerifier(signatureVerifier);
		pkgr.setSigner(signer);
		pkgr.setMetadata(metadata);
	}
	
	protected static class Cmd {
		public String cmdStr, cmdLine;
		public HashMap<String, String> hashCmdArgs = new HashMap<String, String>();
	}
	
	protected static class MetadataInfo {
		public String fileFormatCd, binaryEncodingSchemeCd, entCommCd;
	}
	
	public static MetadataInfo getMetadataInfo(Cmd cmd) {
		//fileFormatCd=XML|TXT|PDF|JPG|RTF, binaryEncodingSchemeCd=NONE|BASE64, fatcaEntCommCd=NTF|RPT|CAR|REG
		MetadataInfo md = new MetadataInfo();
		String key;
		md.fileFormatCd = md.binaryEncodingSchemeCd = md.entCommCd = null;
		Iterator<String> keys = cmd.hashCmdArgs.keySet().iterator();
		while (keys.hasNext() && (md.fileFormatCd == null || md.binaryEncodingSchemeCd == null || md.entCommCd == null)) {
			key = keys.next();
			if ("fileFormat".equalsIgnoreCase(key) || 
					"fileFormatCd".equalsIgnoreCase(key))
				md.fileFormatCd = cmd.hashCmdArgs.get(key);
			else if ("binaryEncoding".equalsIgnoreCase(key) || 
					"binaryEncodingScheme".equalsIgnoreCase(key) || 
					"binaryEncodingSchemeCd".equalsIgnoreCase(key))
				md.binaryEncodingSchemeCd = cmd.hashCmdArgs.get(key);	
			else if ("commType".equalsIgnoreCase(key) || 
					"communicationType".equalsIgnoreCase(key) ||
					"commTypeCd".equalsIgnoreCase(key) || 
					"entCommType".equalsIgnoreCase(key) || 
					"entCommTypeCd".equalsIgnoreCase(key) ||
					"entCommCd".equalsIgnoreCase(key) || 
					"fatcaEntComm".equalsIgnoreCase(key) || 
					"fatcaEntCommCd".equalsIgnoreCase(key) || 
					"fatcaEntCommType".equalsIgnoreCase(key) ||
					"fatcaEntCommTypeCd".equalsIgnoreCase(key))
				md.entCommCd = cmd.hashCmdArgs.get(key);	
		}
		return md;
	}

	protected void readConfigAndExceuteCommands() throws Exception {
		readConfigAndExceuteCommands(defaultConfigFile);
	}
	
	protected void readConfigAndExceuteCommands(String conf) throws Exception {
		String senderPrivateKSType, senderPublicKSType, receiverPrivateKSType, receiverPublicKSType, 
		approverPrivateKSType, approverPublicKSType, senderPrivateKSPwd, senderPublicKSPwd, 
		receiverPrivateKSPwd, receiverPublicKSPwd, approverPrivateKSPwd, approverPublicKSPwd,
		senderPrivateKSFile = null, senderPublicKSFile = null, receiverPrivateKSFile = null, 
		receiverPublicKSFile = null, approverPrivateKSFile = null, approverPublicKSFile = null,  
		senderPrivateKeyPwd = null, receiverPrivateKeyPwd = null, approverPrivateKeyPwd = null, 
		senderPrivateKeyAlias = null, senderPublicKeyAlias = null, receiverPrivateKeyAlias = null, 
		receiverPublicKeyAlias = null, approverPrivateKeyAlias = null, approverPublicKeyAlias=null, 
		receiverPublicCertName = null, senderPublicCertName = null, approverPublicCertName = null;
					
		try {
			ArrayList<Cmd> listCmds = new ArrayList<Cmd>();
			BufferedReader br = new BufferedReader(new FileReader(conf));
			String line, key, val;
			StringTokenizer st;
			int pos;
			Cmd cmd;
			boolean isComment = false;
			
			senderPrivateKSType = senderPublicKSType = receiverPrivateKSType = receiverPublicKSType = 
					approverPrivateKSType=approverPublicKSType = UtilShared.defaultKeystoreType;
			senderPrivateKSPwd = senderPublicKSPwd = receiverPrivateKSPwd = receiverPublicKSPwd = 
					approverPrivateKSPwd = approverPublicKSPwd = "pwd123";
			
			while((line = br.readLine()) != null) {
				line = line.trim();
				if (line.startsWith("//") || line.startsWith("!"))
					continue;
				if (line.startsWith("/*") && !isComment) {
					isComment = true;
					continue;
				} else if (line.startsWith("*/") && isComment) {
					isComment = false;
					line = line.substring(2).trim();
				}
				if ("".equals(line) || isComment)
					continue;
				key = val = null; 
				st = new StringTokenizer(line, " =");
				if (!st.hasMoreTokens())
					continue;
				else {
					key = st.nextToken();
					if (st.hasMoreTokens())
						val = line.substring(key.length()+1).trim();
				}
				
				if (val != null && ("xmlSchema".equalsIgnoreCase(key) || "schema".equalsIgnoreCase(key) ||
						"schemaForXmlValidation".equalsIgnoreCase(key) || "xmlValidationSchema".equalsIgnoreCase(key) ))
					xmlSchema = val;
				else if (val != null && ("xmlStartElemForSchemaValidation".equalsIgnoreCase(key) || 
						"xmlStartElem".equalsIgnoreCase(key) || "xmlStartElemForSchema".equalsIgnoreCase(key) ||
						"xmlStartElemSchema".equalsIgnoreCase(key)))
					xmlStartElemForSchemaValidation = val;
				else if (("validateAllXMLSchema".equalsIgnoreCase(key) || 
						"validateXMLSchema".equalsIgnoreCase(key)) && "true".equals(val))
					isValidateAllXMLSchema = true;
				else if (val != null && "senderPrivateKSType".equalsIgnoreCase(key))
					senderPrivateKSType = val;
				else if (val != null && "senderPublicKSType".equalsIgnoreCase(key))
					senderPublicKSType = val;
				else if (val != null && "receiverPrivateKSType".equalsIgnoreCase(key))
					receiverPrivateKSType = val;
				else if (val != null && "receiverPublicKSType".equalsIgnoreCase(key))
					receiverPublicKSType = val;
				else if (val != null && "approverPrivateKSType".equalsIgnoreCase(key))
					approverPrivateKSType = val;
				else if (val != null && "approverPublicKSType".equalsIgnoreCase(key))
					approverPublicKSType = val;
				else if (val != null && "senderPrivateKSFile".equalsIgnoreCase(key)) {
					senderPrivateKSFile = val;
					if (senderPrivateKSFile.endsWith(".jks"))
						senderPrivateKSType = "jks";
				} else if (val != null && "senderPublicKSFile".equalsIgnoreCase(key)) {
					senderPublicKSFile = val;
					if (senderPublicKSFile.endsWith(".jks"))
						senderPublicKSType = "jks";
				} else if (val != null && "receiverPrivateKSFile".equalsIgnoreCase(key)) {
					receiverPrivateKSFile = val;
					if (receiverPrivateKSFile.endsWith(".jks"))
						receiverPrivateKSType = "jks";
				} else if (val != null && "receiverPublicKSFile".equalsIgnoreCase(key)) {
					receiverPublicKSFile = val;
					if (receiverPublicKSFile.endsWith(".jks"))
						receiverPublicKSType = "jks";
				} else if (val != null && "approverPrivateKSFile".equalsIgnoreCase(key)) {
					approverPrivateKSFile = val;
					if (approverPrivateKSFile.endsWith(".jks"))
						approverPrivateKSType = "jks";
				} else if (val != null && "approverPublicKSFile".equalsIgnoreCase(key)) {
					approverPublicKSFile = val;
					if (approverPublicKSFile.endsWith(".jks"))
						approverPublicKSType = "jks";
				} else if (val != null && "senderPrivateKSPwd".equalsIgnoreCase(key))
					senderPrivateKSPwd = val;
				else if (val != null && "senderPublicKSPwd".equalsIgnoreCase(key))
					senderPublicKSPwd = val;
				else if (val != null && "receiverPublicCertName".equalsIgnoreCase(key))
					receiverPublicCertName = val;
				else if (val != null && "senderPublicCertName".equalsIgnoreCase(key))
					senderPublicCertName = val;
				else if (val != null && "approverPublicCertName".equalsIgnoreCase(key))
					approverPublicCertName = val;
				else if (val != null && "receiverPrivateKSPwd".equalsIgnoreCase(key))
					receiverPrivateKSPwd = val;
				else if (val != null && "receiverPublicKSPwd".equalsIgnoreCase(key))
					receiverPublicKSPwd = val;
				else if (val != null && "approverPrivateKSPwd".equalsIgnoreCase(key))
					approverPrivateKSPwd = val;
				else if (val != null && "approverPublicKSPwd".equalsIgnoreCase(key))
					approverPublicKSPwd = val;
				else if (val != null && "senderPrivateKeyPwd".equalsIgnoreCase(key))
					senderPrivateKeyPwd = val;
				else if (val != null && "receiverPrivateKeyPwd".equalsIgnoreCase(key))
					receiverPrivateKeyPwd = val;
				else if (val != null && "approverPrivateKeyPwd".equalsIgnoreCase(key))
					approverPrivateKeyPwd = val;
				else if (val != null && "senderPrivateKeyAlias".equalsIgnoreCase(key))
					senderPrivateKeyAlias = val;
				else if (val != null && "senderPublicKeyAlias".equalsIgnoreCase(key))
					senderPublicKeyAlias = val;
				else if (val != null && "receiverPrivateKeyAlias".equalsIgnoreCase(key))
					receiverPrivateKeyAlias = val;
				else if (val != null && "receiverPublicKeyAlias".equalsIgnoreCase(key))
					receiverPublicKeyAlias = val;
				else if (val != null && "approverPrivateKeyAlias".equalsIgnoreCase(key))
					approverPrivateKeyAlias = val;
				else if (val != null && "approverPublicKeyAlias".equalsIgnoreCase(key))
					approverPublicKeyAlias = val;
				else if (val != null && "senderGiin".equalsIgnoreCase(key))
					senderGiin = val;
				else if (val != null && "receiverGiin".equalsIgnoreCase(key))
					receiverGiin = val;
				else if (val != null && "approverGiin".equalsIgnoreCase(key))
					approverGiin = val;
				else if (val != null && "taxYear".equalsIgnoreCase(key))
					taxyear = Integer.parseInt(val);
				else {
					cmd = new Cmd();
					cmd.cmdLine = line;
					cmd.cmdStr = key;
					listCmds.add(cmd);
					if ("stop".equalsIgnoreCase(cmd.cmdStr))
						break;
					if (val != null) {
						st = new StringTokenizer(val);
						while(st.hasMoreTokens()) {
							val = st.nextToken();
							pos = val.indexOf('=');
							if (pos != -1)
								cmd.hashCmdArgs.put(val.substring(0,pos).toLowerCase(), val.substring(pos+1));
							else {
								cmd.hashCmdArgs.put(cmd.cmdStr, val);
								break;
							}
						}
					} else
						cmd.hashCmdArgs.put(cmd.cmdStr, "");
				}
			}
			br.close();
			
			if ("pkcs12".equals(receiverPrivateKSType) && receiverPrivateKeyPwd == null)
				receiverPrivateKeyPwd = receiverPrivateKSPwd;
			if ("pkcs12".equals(senderPrivateKSType) && senderPrivateKeyPwd == null)
				senderPrivateKeyPwd = senderPrivateKSPwd;
			if ("pkcs12".equals(approverPrivateKSType) && senderPrivateKeyPwd == null)
				approverPrivateKeyPwd = approverPrivateKSPwd;
			if (receiverPublicKSType != null && receiverPublicKSFile != null && receiverPublicKSPwd != null)
				try{receiverPublicCert = UtilShared.getCert(receiverPublicKSType, receiverPublicKSFile, receiverPublicKSPwd, receiverPublicKeyAlias);} catch(Exception e) {}
			if (receiverPublicCert == null && receiverPublicCertName != null)
				try{receiverPublicCert = (X509Certificate)UtilShared.getCert(receiverPublicCertName);} catch(Exception e) {}
			if (senderPublicKSType != null && senderPublicKSFile != null && senderPublicKSPwd != null)
				try{senderPublicCert = UtilShared.getCert(senderPublicKSType, senderPublicKSFile, senderPublicKSPwd, senderPublicKeyAlias);} catch(Exception e) {}
			if (senderPublicCert == null && senderPublicCertName != null)
				try{senderPublicCert = (X509Certificate)UtilShared.getCert(senderPublicCertName);} catch(Exception e) {}
			if (approverPublicKSType != null && approverPublicKSFile != null && approverPublicKSPwd != null)
				try{approverPublicCert = UtilShared.getCert(approverPublicKSType, approverPublicKSFile, approverPublicKSPwd, approverPublicKeyAlias);} catch(Exception e) {}
			if (approverPublicCert == null && approverPublicCertName != null)
				try{approverPublicCert = (X509Certificate)UtilShared.getCert(approverPublicCertName);} catch(Exception e) {}
			if (senderPrivateKSType != null && senderPrivateKSFile != null && senderPrivateKeyPwd != null && senderPrivateKSPwd != null)
				try{senderPrivateKey = UtilShared.getPrivateKey(senderPrivateKSType, senderPrivateKSFile, senderPrivateKSPwd, senderPrivateKeyPwd, senderPrivateKeyAlias);} catch(Exception e) {}
			if (receiverPrivateKSType != null && receiverPrivateKSFile != null && receiverPrivateKeyPwd != null && receiverPrivateKSPwd != null)
				try{receiverPrivateKey = UtilShared.getPrivateKey(receiverPrivateKSType, receiverPrivateKSFile, receiverPrivateKSPwd, receiverPrivateKeyPwd, receiverPrivateKeyAlias);} catch(Exception e) {}
			if (approverPrivateKSType != null && approverPrivateKSFile != null && approverPrivateKeyPwd != null && approverPrivateKSPwd != null)
				try{approverPrivateKey = UtilShared.getPrivateKey(approverPrivateKSType, approverPrivateKSFile, approverPrivateKSPwd, approverPrivateKeyPwd, approverPrivateKeyAlias);} catch(Exception e) {}
			
			processCmds(listCmds);
			
			if (isVerifyAllSignature && signatureVerifier != null)
				logger.info("all signature verification=" + signatureVerifier.getVerificationFlag());
		} catch(Exception e) {
			e.printStackTrace();
			throw e;
		}
	}
	
	protected void processCmds(ArrayList<Cmd> listCmds) throws Exception {
		Cmd cmd;
		String input, output = null, key;
		int taxyear = -1;
		MetadataInfo md;
		
		for (int i = 0; i < listCmds.size(); i++) {
			cmd = listCmds.get(i);
			if ("stop".equalsIgnoreCase(cmd.cmdStr) || "exit".equalsIgnoreCase(cmd.cmdStr))
				break;
			if ("pause".equalsIgnoreCase(cmd.cmdStr)) {
				System.out.println("Press a key...");
				System.in.read();
				continue;
			} else if ("excludeKeyInfoFromSignature".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("excludeKeyInfoFromSignature", "true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
				continue;
			} else if ("setBufSize".equalsIgnoreCase(cmd.cmdStr)) {
				int intval = Integer.parseInt(cmd.hashCmdArgs.get(cmd.cmdStr));
				if (intval > 0)
					UtilShared.defaultBufSize = intval;
				continue;
			} else if ("signaturePrefix".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("signaturePrefix", cmd.hashCmdArgs.get(cmd.cmdStr));
				continue;
			} else if ("sigRefIdPos".equalsIgnoreCase(cmd.cmdStr)) {
				//Object|SignatureProperty|SignatureProperties
				signer.setProperty("sigRefIdPos", cmd.hashCmdArgs.get(cmd.cmdStr));
				continue;
			} else if ("sigXmlTransform".equalsIgnoreCase(cmd.cmdStr)) {
				//Inclusive|InclusiveWithComments|Exclusive|ExclusiveWithComments|None
				signer.setProperty("sigXmlTransform", cmd.hashCmdArgs.get(cmd.cmdStr));
				continue;
			} else if ("wrapperNS".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("wrapperNS", cmd.hashCmdArgs.get(cmd.cmdStr));
				continue;
			} else if ("wrapperPrefix".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("wrapperPrefix", cmd.hashCmdArgs.get(cmd.cmdStr));
				continue;
			} else if ("wrapperXsiSchemaLoc".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("wrapperXsiSchemaLoc", cmd.hashCmdArgs.get(cmd.cmdStr));
				continue;
			} else if ("xmlChunkStreamingSize".equalsIgnoreCase(cmd.cmdStr)) {
				int intval = Integer.parseInt(cmd.hashCmdArgs.get(cmd.cmdStr));
				if (intval > 0)
					UtilShared.defaultChunkStreamingSize = intval;
				continue;
			} else if ("isWrapperXsi".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("isWrapperXsi", "true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
				continue;
			} else if ("isWrapperXsiSchemaLoc".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("isWrapperXsiSchemaLoc", "true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
				continue;
			} else if ("isAddSignaturePropTimestamp".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("isAddSignaturePropTimestamp", "true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
				continue;
			} else if ("setSigningDebugBuf".equalsIgnoreCase(cmd.cmdStr) || "setDebugBuf".equalsIgnoreCase(cmd.cmdStr)) {
				signer.setProperty("setSigningDebugBuf", null);
				continue;
			} else if ("getSigningDebugBuf".equalsIgnoreCase(cmd.cmdStr) || "getDebugBuf".equalsIgnoreCase(cmd.cmdStr)) {
				logger.info(signer.getProperty("getSigningDebugBuf").toString());
				continue;
			} else if ("validateAllSignature".equalsIgnoreCase(cmd.cmdStr) || "isValidateAllSignature".equalsIgnoreCase(cmd.cmdStr) ||
					"verifyAllSignature".equalsIgnoreCase(cmd.cmdStr) || "isVerifyAllSignature".equalsIgnoreCase(cmd.cmdStr)) {
				if ("true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))) {
					isVerifyAllSignature = true;
					signer.setProperty("verifyAllSignature", true);
				}
				continue;
			} else if ("keepSignedXmlAfterSignAndCreatePkgFlag".equalsIgnoreCase(cmd.cmdStr)) {
				pkgr.setProperty("keepSignedXmlAfterSignAndCreatePkgFlag", "true".equals(cmd.hashCmdArgs.get(cmd.cmdStr))?true:false);
				continue;
			}
			
			key = "input";
			if (cmd.hashCmdArgs.containsKey(key))
				input = cmd.hashCmdArgs.get(key);
			else
				input = cmd.hashCmdArgs.get(cmd.cmdStr);
			if (input == null || "".equals(input))
				input = output;
			
			output = null;
			key = "output";
			
			if (cmd.hashCmdArgs.containsKey(key))
				output = cmd.hashCmdArgs.get(key);
			/*
			if (input == null) {
				logger.error("ERROR: invalid cmd or missing input. cmd=" + cmd.cmdStr);
				continue;
			}
			*/

			if ("signBinary".equalsIgnoreCase(cmd.cmdStr) || 
					"signBinaryStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					 "signXml".equalsIgnoreCase(cmd.cmdStr) || 
					 "signXmlStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					"signText".equalsIgnoreCase(cmd.cmdStr) || "signTextStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					"wrapBinaryInXmlAndSign".equalsIgnoreCase(cmd.cmdStr) || 
					"wrapBinaryInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr) || 
					"wrapTextInXmlAndSign".equalsIgnoreCase(cmd.cmdStr) || 
					"wrapTextInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr)) {
				if (output == null)
					output = input + ".signed.xml";
				processSignatureCmds(input, output, cmd);
			}
			else if ("createPkg".equalsIgnoreCase(cmd.cmdStr) || 
					"createPkgWithApprover".equalsIgnoreCase(cmd.cmdStr) ||
					"signAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) || 
					"signAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) ||
					"signAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) || 
					"signAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					"signBinaryAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) ||
					"signBinaryAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) || 
					"signTextAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) || 
					"signTextAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) || 
					"signBinaryAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) || 
					"signBinaryAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					"signTextAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) || 
					"signTextAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr))
				output = processPkgCmds(input, cmd);
			else if ("validateSchema".equalsIgnoreCase(cmd.cmdStr) || "verifySchema".equalsIgnoreCase(cmd.cmdStr))
				processValidateSchemaCmd(cmd);
			else if ("validateSignature".equalsIgnoreCase(cmd.cmdStr) || "validateSig".equalsIgnoreCase(cmd.cmdStr) ||
					"verifySignature".equalsIgnoreCase(cmd.cmdStr) || "verifySig".equalsIgnoreCase(cmd.cmdStr) ||
					"validateSignatureStreaming".equalsIgnoreCase(cmd.cmdStr) || "validateSigStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					"verifySignatureStreaming".equalsIgnoreCase(cmd.cmdStr) || "verifySigStreaming".equalsIgnoreCase(cmd.cmdStr) ||
					"validateSignatureStream".equalsIgnoreCase(cmd.cmdStr) || "validateSigStream".equalsIgnoreCase(cmd.cmdStr) ||
					"verifySignatureStreaming".equalsIgnoreCase(cmd.cmdStr) || "verifySigStream".equalsIgnoreCase(cmd.cmdStr))
				processVerifySignatureCmd(input, cmd);
			else if ("unpack".equalsIgnoreCase(cmd.cmdStr) || 
					"unpackForApprover".equalsIgnoreCase(cmd.cmdStr))
				processUnpackCmd(input, cmd);
			else if ("createBinaryFromSignedBase64Binary".equalsIgnoreCase(cmd.cmdStr)) {
				if (output == null)
					output = input + ".bin";
				UtilShared.createBinaryFileFromSignedBase64BinaryFile(input, output);
			} else if ("createZipPkg".equalsIgnoreCase(cmd.cmdStr)) {
				if (output == null)
					output = senderGiin + "_Payload.zip";
				processCreateZipCmd(input, output, cmd);
			} else if ("encryptZipPkg".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null  
					&& receiverPublicCert != null) {
				md = getMetadataInfo(cmd);
				output = pkgr.encryptZipPkg(input, senderGiin, receiverGiin, receiverPublicCert, 
						null, null, taxyear, md.fileFormatCd, md.binaryEncodingSchemeCd, md.entCommCd);
			} else if ("encryptZipPkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null 
					&& receiverGiin != null  && receiverPublicCert != null && approverGiin != null 
					&& approverPublicCert != null) {
				md = getMetadataInfo(cmd);
				output = pkgr.encryptZipPkg(input, senderGiin, receiverGiin, receiverPublicCert, 
						approverGiin, approverPublicCert, taxyear, md.fileFormatCd, md.binaryEncodingSchemeCd, md.entCommCd);
			}
			else if (("unencryptZipPkg".equalsIgnoreCase(cmd.cmdStr) || 
					"decryptZipPkg".equalsIgnoreCase(cmd.cmdStr))&& receiverPrivateKey != null) {
				ArrayList<String> list = pkgr.unencryptZipPkg(input, receiverPrivateKey, false);
				for (int idx = 0; idx < list.size(); idx++) {
					if (list.get(idx).toLowerCase().contains("payload")) {
						output = list.get(idx);
						break;
					}
				}
			} else if (("unencryptZipPkgForApprover".equalsIgnoreCase(cmd.cmdStr) || "decryptZipPkgForApprover".equalsIgnoreCase(cmd.cmdStr)) && approverPrivateKey != null) {
				ArrayList<String> list = pkgr.unencryptZipPkg(input, approverPrivateKey, true);
				for (int idx = 0; idx < list.size(); idx++) {
					if (list.get(idx).toLowerCase().contains("payload")) {
						output = list.get(idx);
						break;
					}
				}
			} else if ("extractZipPkg".equalsIgnoreCase(cmd.cmdStr))
				pkgr.unzipFile(input);
			else if ("metadata".equalsIgnoreCase(cmd.cmdStr) || "setMetadataInfo".equalsIgnoreCase(cmd.cmdStr))
				processMetadataCmd(cmd);
			else if ("extractUnsignedXmlFromSignedXml".equalsIgnoreCase(cmd.cmdStr))
				processExtractUnsignedXmlFromSignedXml(cmd);
			else
				logger.error("ERROR: unable to execute " + cmd.cmdStr + "....there may be missing info to execute cmd");
			logger.info("finished...cmd=" + cmd.cmdStr + (input==null?"":" input=" + input) + (output==null?"":", output=" + output) + " [" + cmd.cmdLine + "]");
		}
	}
	
	protected void processExtractUnsignedXmlFromSignedXml(Cmd cmd) throws Exception {
		String signedXml = null, unsignedXmlStartElem = null, outUnsignedXml = null;
		String key;
		key = "signedXml".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			signedXml = cmd.hashCmdArgs.get(key);
		key = "unsignedXmlStartElem".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			unsignedXmlStartElem = cmd.hashCmdArgs.get(key);
		key = "outUnsignedXml".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			outUnsignedXml = cmd.hashCmdArgs.get(key);
		if (signedXml == null || unsignedXmlStartElem == null || outUnsignedXml == null)
			logger.error("ERROR: unable to execute " + cmd.cmdStr + "....signedXml == null || unsignedXmlStartElem == null || outUnsignedXml == null ...there may be missing info,  to execute cmd");
		else
			UtilShared.extractUnsignedXmlFromSignedXml(signedXml, unsignedXmlStartElem, outUnsignedXml);
	}
	
	protected void processSignatureCmds(String input, String output, Cmd cmd) throws Exception {
		X509Certificate sigPublicCert; 
		PrivateKey sigPrivateKey;
		String key, val;
		
		if (isValidateAllXMLSchema) {
			if (xmlSchema != null && xmlStartElemForSchemaValidation != null) {
				boolean flag = UtilShared.validateSchema(input, xmlSchema, xmlStartElemForSchemaValidation);
				logger.info("schema validation=" + flag + ", xml=" + input + ", schema=" + xmlSchema + 
						", xmlStartElemForSchemaValidation=" + xmlStartElemForSchemaValidation);
			} else {
				logger.info("schema wasn't validated. xml=" + input + ", schema=" + xmlSchema + 
						", xmlStartElemForSchemaValidation=" + xmlStartElemForSchemaValidation);
			}
		}
		
		sigPublicCert = senderPublicCert;
		sigPrivateKey = senderPrivateKey;
		key = "sigPublicCert".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) {
			val = cmd.hashCmdArgs.get(key);
			if ("senderPublicCert".equalsIgnoreCase(val) || "senderPubCert".equalsIgnoreCase(val))
				sigPublicCert = senderPublicCert;
			else if ("receiverPublicCert".equalsIgnoreCase(val) || "receiverPubCert".equalsIgnoreCase(val))
				sigPublicCert = receiverPublicCert;
			else if ("approverPublicCert".equalsIgnoreCase(val) || "approverPubCert".equalsIgnoreCase(val))
				sigPublicCert = approverPublicCert;
		}
		key = "sigKey".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) {
			val = cmd.hashCmdArgs.get(key);
			if ("senderPrivateKey".equalsIgnoreCase(val))
				sigPrivateKey = senderPrivateKey;
			else if ("receiverPrivateKey".equalsIgnoreCase(val))
				sigPrivateKey = receiverPrivateKey;
			else if ("approverPrivateKey".equalsIgnoreCase(val))
				sigPrivateKey = approverPrivateKey;
		}
		if ("signText".equalsIgnoreCase(cmd.cmdStr))
			signer.signTextFile(input, output, sigPrivateKey, sigPublicCert);
		else if ("signTextStreaming".equalsIgnoreCase(cmd.cmdStr))
			signer.signTextFileStreaming(input, output, sigPrivateKey, sigPublicCert);
		else if ("signBinary".equalsIgnoreCase(cmd.cmdStr))
			signer.signBinaryFile(input, output, sigPrivateKey, sigPublicCert);
		else if ("signBinaryStreaming".equalsIgnoreCase(cmd.cmdStr))
			signer.signBinaryFileStreaming(input, output, senderPrivateKey, senderPublicCert);
		else if ("signXml".equalsIgnoreCase(cmd.cmdStr))
			signer.signXmlFile(input, output, senderPrivateKey, senderPublicCert);
		else if ("signXmlStreaming".equalsIgnoreCase(cmd.cmdStr))
			signer.signXmlFileStreaming(input, output, senderPrivateKey, senderPublicCert);
		else if ("wrapBinaryInXmlAndSign".equalsIgnoreCase(cmd.cmdStr))
			signer.wrapBinaryFileInXmlAndSign(input, output, senderPrivateKey, senderPublicCert);
		else if ("wrapBinaryInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr))
			signer.wrapBinaryFileInXmlAndSignStreaming(input, output, senderPrivateKey, senderPublicCert);
		else if ("wrapTextInXmlAndSign".equalsIgnoreCase(cmd.cmdStr))
			signer.wrapTextFileInXmlAndSign(input, output, senderPrivateKey, senderPublicCert);
		else if ("wrapTextInXmlAndSignStreaming".equalsIgnoreCase(cmd.cmdStr) )
			signer.wrapTextFileInXmlAndSignStreaming(input, output, senderPrivateKey, senderPublicCert);
		else 
			logger.error("ERROR: unable to execute " + cmd.cmdStr + "....there may be missing info to execute cmd");
	}
	
	protected String processPkgCmds(String input, Cmd cmd) throws Exception {
		MetadataInfo md = getMetadataInfo(cmd);
		String output = null;

		if (isValidateAllXMLSchema) {
			if (xmlSchema != null && xmlStartElemForSchemaValidation != null) {
				boolean flag = UtilShared.validateSchema(input, xmlSchema, xmlStartElemForSchemaValidation);
				logger.info("schema validation=" + flag + ", xml=" + input + ", schema=" + xmlSchema + 
						", xmlStartElemForSchemaValidation=" + xmlStartElemForSchemaValidation);
			} else {
				logger.info("schema wasn't validated. xml=" + input + ", schema=" + xmlSchema + 
						", xmlStartElemForSchemaValidation=" + xmlStartElemForSchemaValidation);
			}
		}
		
		if ("createPkg".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null && receiverPublicCert != null && taxyear != -1)
			output = pkgr.createPkg(input, senderGiin, receiverGiin, receiverPublicCert, taxyear, md.fileFormatCd, md.binaryEncodingSchemeCd, md.entCommCd);
		else if ("createPkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderGiin != null && receiverGiin != null 
				&& approverGiin != null && receiverPublicCert != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.createPkgWithApprover(input, senderGiin, receiverGiin, receiverPublicCert, approverGiin, 
					approverPublicCert, taxyear, md.fileFormatCd, md.binaryEncodingSchemeCd, md.entCommCd);
		else if ("signAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
			output = pkgr.signAndCreatePkg(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, taxyear, md.entCommCd);
		else if ("signAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.signAndCreatePkgWithApprover(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
					approverGiin, approverPublicCert, taxyear, md.entCommCd);
		else if ("signAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
			output = pkgr.signAndCreatePkgStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, taxyear, md.entCommCd);
		else if ("signAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.signAndCreatePkgWithApproverStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
					approverGiin, approverPublicCert, taxyear, md.entCommCd);
		else if ("signBinaryAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
			output = pkgr.signBinaryFileAndCreatePkg(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, taxyear, 
					md.fileFormatCd, md.entCommCd);
		else if ("signBinaryAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.signBinaryFileAndCreatePkgWithApprover(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
					approverGiin, approverPublicCert, taxyear, md.fileFormatCd, md.entCommCd);
		else if ("signTextAndCreatePkg".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
			output = pkgr.signTextFileAndCreatePkg(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, taxyear, md.entCommCd);
		else if ("signTextAndCreatePkgWithApprover".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.signTextFileAndCreatePkgWithApprover(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, approverGiin, approverPublicCert, taxyear, md.entCommCd);
		else if ("signBinaryAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
			output = pkgr.signBinaryFileAndCreatePkgStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, taxyear, md.fileFormatCd, md.entCommCd);
		else if ("signBinaryAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.signBinaryFileAndCreatePkgWithApproverStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, receiverPublicCert, 
					approverGiin, approverPublicCert, taxyear, md.fileFormatCd, md.entCommCd);
		else if ("signTextAndCreatePkgStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && taxyear != -1)
			output = pkgr.signTextFileAndCreatePkgStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, taxyear, md.entCommCd);
		else if ("signTextAndCreatePkgWithApproverStreaming".equalsIgnoreCase(cmd.cmdStr) && senderPrivateKey != null && senderPublicCert != null && 
				senderGiin != null && receiverGiin != null  && receiverPublicCert != null && approverGiin != null && approverPublicCert != null && taxyear != -1)
			output = pkgr.signTextFileAndCreatePkgWithApproverStreaming(input, senderPrivateKey, senderPublicCert, senderGiin, receiverGiin, 
					receiverPublicCert, approverGiin, approverPublicCert, taxyear, md.entCommCd);
		else 
			logger.error("ERROR: unable to execute " + cmd.cmdStr + "....there may be missing info to execute cmd");
		return output;
	}
	
	protected void processValidateSchemaCmd(Cmd cmd) throws Exception {
		//validateSchema xmlFile=<xml> schemaFile=<schema> startElem={urn:oecd:ties:fatca:v2}FATCA_OECD
		String startElem = xmlStartElemForSchemaValidation, schemaFile = xmlSchema,  xmlFile = null;
		String key = "xmlFile".toLowerCase();
		if (!cmd.hashCmdArgs.containsKey(key))
			key = "xml".toLowerCase();
		if (!cmd.hashCmdArgs.containsKey(key))
			key = "input".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) 
			xmlFile = cmd.hashCmdArgs.get(key);
		key = "schemaFile".toLowerCase();
		if (!cmd.hashCmdArgs.containsKey(key))
			key = "schema".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) 
			schemaFile = cmd.hashCmdArgs.get(key);
		key = "startElem".toLowerCase();
		if (!cmd.hashCmdArgs.containsKey(key))
			key = "start".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) 
			startElem = cmd.hashCmdArgs.get(key);
		if (xmlFile == null || schemaFile == null)
			logger.error("xmlFile or schemaFile is null [" + cmd.cmdLine + "]");
		else {
			boolean flag = UtilShared.validateSchema(xmlFile, schemaFile, startElem);
			logger.info("schema validation=" + flag);
		}
	}
	
	protected void processVerifySignatureCmd(String input, Cmd cmd) throws Exception {
		X509Certificate sigVerifyCert = null;
		String val, key = "sigPublicCert".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) {
			val = cmd.hashCmdArgs.get(key);
			if ("senderPublicCert".equalsIgnoreCase(val) || "senderPubCert".equalsIgnoreCase(val))
				sigVerifyCert = senderPublicCert;
			else if ("receiverPublicCert".equalsIgnoreCase(val) || "receiverPubCert".equalsIgnoreCase(val))
				sigVerifyCert = receiverPublicCert;
			else if ("approverPublicCert".equalsIgnoreCase(val) || "approverPubCert".equalsIgnoreCase(val))
				sigVerifyCert = approverPublicCert;
			else
				try{sigVerifyCert = (X509Certificate)UtilShared.getCert(val);}catch(Exception e){}
		}
		boolean flag = false;
		if (cmd.cmdStr.toLowerCase().contains("stream"))
			flag = signatureVerifier.verifySignatureStreaming(input, (sigVerifyCert == null ? null : sigVerifyCert.getPublicKey()));
		else
			flag = signatureVerifier.verifySignature(input, (sigVerifyCert == null ? null : sigVerifyCert.getPublicKey()));
		logger.info("signature verification=" + flag);
	}
	
	protected void processUnpackCmd(String input, Cmd cmd) throws Exception {
		PrivateKey unpackPrivateKey = null;
		String val, key = "unpackPrivateKey".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key)) {
			val = cmd.hashCmdArgs.get(key);
			if ("receiverPrivateKey".equalsIgnoreCase(val))
				unpackPrivateKey = receiverPrivateKey;
			else if ("approverPrivateKey".equalsIgnoreCase(val))
				unpackPrivateKey = approverPrivateKey;
			else if ("senderPrivateKey".equalsIgnoreCase(val))
				unpackPrivateKey = senderPrivateKey;
		}
		if ("unpack".equalsIgnoreCase(cmd.cmdStr))
			pkgr.unpack(input, (unpackPrivateKey==null?receiverPrivateKey:unpackPrivateKey));
		else if ("unpackForApprover".equalsIgnoreCase(cmd.cmdStr))
			pkgr.unpackForApprover(input, (unpackPrivateKey==null?approverPrivateKey:unpackPrivateKey));
	}
	
	protected void processCreateZipCmd(String input, String output, Cmd cmd) throws Exception {
		String[] files = null;
		StringTokenizer st = new StringTokenizer(input, "|");
		files = new String[st.countTokens()];
		for (int j = 0; j < files.length; j++)
			files[j] = st.nextToken();
		if (files != null && files.length > 0)
			pkgr.createZipFile(files, output);
		else if (senderGiin != null)
			pkgr.createZipPkg(input, senderGiin, output);
	}
	
	protected void processMetadataCmd(Cmd cmd) throws Exception {
		String email = null, fileRevisionId = null, origIDESTranId = null;
		String key = "email".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			email = cmd.hashCmdArgs.get(key);
		key = "fileRevisionId".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			fileRevisionId = cmd.hashCmdArgs.get(key);
		key = "origIDESTransId".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			origIDESTranId = cmd.hashCmdArgs.get(key);
		key = "origTransId".toLowerCase();
		if (cmd.hashCmdArgs.containsKey(key))
			origIDESTranId = cmd.hashCmdArgs.get(key);
		pkgr.setMetadataInfo(email, fileRevisionId, origIDESTranId);
	}
	
	public static void main(String[] args) throws Exception {
		Date starttime = new Date();
		FATCADataPrepTool tool = new FATCADataPrepTool();
		if (System.getProperty("jsr105Provider") != null) {
			Provider provider = (Provider)Class.forName(System.getProperty("jsr105Provider")).newInstance();
			tool.signer.setProperty("setDefaultSignatureFactoryProvider", provider);
	    }
        if (args.length > 0)
			tool.readConfigAndExceuteCommands(args[0]);
		else
			tool.readConfigAndExceuteCommands();
        tool.logger.info(UtilShared.getElapsedTime(starttime));
	}
}
