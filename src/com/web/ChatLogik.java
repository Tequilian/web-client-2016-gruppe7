package com.web;

import static us.monoid.web.Resty.data;
import static us.monoid.web.Resty.form;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import us.monoid.json.JSONArray;
import us.monoid.json.JSONException;
import us.monoid.json.JSONObject;
import us.monoid.web.JSONResource;
import us.monoid.web.Resty;

public class ChatLogik {

	public ArrayList<Message> getAllMsg(String identity) {
		ArrayList<Message> msglist = new ArrayList<Message>();
		JSONResource json = null;
		JSONObject status = null;
		JSONArray allmsg = null;
		Resty r = new Resty();
		String statusCode = "";
		try {
			try {
				json = r.json("http://web2016team7.herokuapp.com/" + identity + "/showallmsg/");
				status = json.object();
			} catch (ClassCastException e3) {
				allmsg = json.array();
			}
			if (status != null) {
				statusCode = status.getString("status_code");
				if (statusCode.equals("461")) {
					return null;
				}
			} else {
				for (int i = 0; i < allmsg.length(); i++) {
					Message msg = new Message();
					msg.setId(allmsg.getJSONObject(i).getString("message_id"));
					msg.setSender(allmsg.getJSONObject(i).getString("identity"));
					String read = allmsg.getJSONObject(i).getString("read");
					if (read.equals("true")) {
						msg.setRead(true);
					} else {
						msg.setRead(false);
					}
					msglist.add(msg);
				}
			}
		} catch (Exception e5) {
			e5.printStackTrace();
		}
		return msglist;
	}
	public String getMsg(String msgid, String email, byte[] privkeyByte){
		
		String sender = "";
		String receiver = "";

		BASE64Encoder myEncoder = new BASE64Encoder();
		BASE64Decoder myDecoder2 = new BASE64Decoder();


		//System.out.println(msgid);

		// get timestamp
		long unixTime = System.currentTimeMillis() / 1000L;
		String strTime = Long.toString(unixTime);

		// get PrivateKey
		PrivateKey privateKey = null;
		try {
			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privkeyByte);
			KeyFactory generator = KeyFactory.getInstance("RSA");
			privateKey = generator.generatePrivate(privateKeySpec);
		} catch (NoSuchAlgorithmException e3) {
			e3.printStackTrace();
		} catch (InvalidKeySpecException e1) {
			e1.printStackTrace();
		}

		// get sig_message über identity und timestamp
		String sig_messageDataString = email + strTime;
		String sig_messageString = "";
		byte[] data = sig_messageDataString.getBytes();
		byte[] sig_message = null;

		try {
			Signature sig1 = Signature.getInstance("SHA256withRSA");
			sig1.initSign(privateKey);
			sig1.update(data);
			sig_message = sig1.sign();
		} catch (InvalidKeyException e2) {
			e2.printStackTrace();
		} catch (NoSuchAlgorithmException e2) {
			e2.printStackTrace();
		} catch (SignatureException e2) {
			e2.printStackTrace();
		}
		sig_messageString = myEncoder.encode(sig_message);

		JSONObject msgRec = new JSONObject();
		Resty r = new Resty();
		try {
			msgRec = r.json("http://web2016team7.herokuapp.com/" + email + "/showmsg",
					form(data("sig_message", sig_messageString), data("message_id", msgid),
							data("timestamp", strTime)))
					.object();
		} catch (Exception e1) {
			e1.printStackTrace();
		}

		String cipherString = "";
		String sig_recipientString = "";
		String ivString = "";
		String key_recipient_encString = "";
		String created_at = "";
		try {
			// pubkey_recipient = pubkeyRec.getString("pubkey_user");
			sender = msgRec.getString("identity");
			cipherString = msgRec.getString("cipher");
			sig_recipientString = msgRec.getString("sig_recipient");
			ivString = msgRec.getString("iv");
			key_recipient_encString = msgRec.getString("key_recipient_enc");
			created_at = msgRec.getString("created_at");
		} catch (JSONException e1) {
			e1.printStackTrace();
		}
		// get Pubkey from Identiy

		JSONObject pubkeySen = new JSONObject();
		String pubkey_senderString = "";
		byte[] pubkey_recipientByte = null;
		try {
			pubkeySen = r.json("http://web2016team7.herokuapp.com/" + sender + "/pubkey").object();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (JSONException e1) {
			e1.printStackTrace();
		}
		try {
			pubkey_senderString = pubkeySen.getString("pubkey_user");
		} catch (JSONException e1) {
			e1.printStackTrace();
		}
		PublicKey pubKey = null;
		try {
			pubkey_recipientByte = myDecoder2.decodeBuffer(pubkey_senderString);
			pubKey = null;
			pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubkey_recipientByte));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e4) {
			e4.printStackTrace();
		}

		byte[] sig_recipientByte = null;
		try {
			sig_recipientByte = myDecoder2.decodeBuffer(sig_recipientString);

			String digSignature = sender + cipherString + ivString + key_recipient_encString;
			Signature sig2 = null;
			try {
				sig2 = Signature.getInstance("SHA256withRSA");
				sig2.initVerify(pubKey);
				sig2.update(digSignature.getBytes());
				// System.out.println(sig2.verify(sig_recipientByte));
			} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e1) {
				e1.printStackTrace();
			}

			if (sig2.verify(sig_recipientByte)) {
				// zeige nachricht an
				byte[] key_recipient_enc = myDecoder2.decodeBuffer(key_recipient_encString);
				byte[] key_recipient = decrypt_rec_priv(privateKey, key_recipient_enc);

				//System.out.println("Tes: " + Arrays.toString(key_recipient));

				// hole iv aus string
				IvParameterSpec ivSpec = null;
				byte[] ivByte = myDecoder2.decodeBuffer(ivString);
				ivSpec = new IvParameterSpec(ivByte);

				// entschlüssel nachricht
				byte[] cipher_enc = myDecoder2.decodeBuffer(cipherString);
				String msg = decryptMSG(key_recipient, cipher_enc, ivSpec);

				if(!msg.equals("")){
					//String string = "January 2, 2010";
					//2016-06-29T15:58:08.639Z
					created_at = created_at.replace("T"," ");
					
					//2016-06-29 15:58:08.639Z
					int i = created_at.indexOf(".");
					created_at = created_at.substring(0, i);

					
					return created_at+"\n"+msg;
				}

			} else {
				return "Signatur falsch";
			}

		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (SignatureException e1) {
			e1.printStackTrace();
		} 
		
		return "Fehler";
	}
	
	public String decryptMSG(byte[] key_recipient, byte[] cipher, IvParameterSpec iv) {
		try {
			SecretKey key_recipient_enc = new SecretKeySpec(key_recipient, 0, key_recipient.length, "AES");
			Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher1.init(Cipher.DECRYPT_MODE, key_recipient_enc, iv);
			byte[] cleartextByte = cipher1.doFinal(cipher);
			return new String(cleartextByte, "UTF-8");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}
	public byte[] decrypt_rec_priv(PrivateKey privKey, byte[] key_recipient_enc) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			return cipher.doFinal(key_recipient_enc);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
}
