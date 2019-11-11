package dsa;

import java.math.BigInteger;
import java.net.URLDecoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>Deterministic DSA signature generation. This is a sample
 * implementation designed to illustrate how deterministic DSA
 * chooses the pseudo-random value k when signing a given message.
 * This implementation was NOT optimized or hardened against
 * side-channel leaks.</p>
 *
 * <p>An instance is created with a hash function name, which must be
 * supported by the underlying Java virtual machine ("SHA-1" and
 * "SHA-256" should work everywhere). The data to sign is input
 * through the {@code update()} methods. The private key is set with
 * {@link #setPrivateKey}. The signature is obtained by calling
 * {@link #sign}; alternatively, {@link #signHash} can be used to
 * sign some data which has been externally hashed. The private key
 * MUST be set before generating the signature itself, but message
 * data can be input before setting the key.</p>
 *
 * <p>Instances are NOT thread-safe. However, once a signature has
 * been generated, the same instance can be used again for another
 * signature; {@link #setPrivateKey} needs not be called again if the
 * private key has not changed. {@link #reset} can also be called to
 * cancel previously input data. Generating a signature with {@link
 * #sign} (not {@link #signHash}) also implicitely causes a
 * reset.</p>
 *
 * <pre>
 * ------------------------------------------------------------------
 * (c) Thomas Pornin 2011. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the authors be
 * held liable for any damages arising from the use of this software.
 * 
 * Permission is granted to anyone to use this software for any
 * purpose, including commercial applications, and to alter it and
 * redistribute it freely, subject to no restriction.
 * 
 * Technical remarks and questions can be addressed to:
 * pornin@bolet.org
 * ------------------------------------------------------------------
 * </pre>
 */

public class DeterministicDSA {

        private String macName;
        private MessageDigest dig;
        private Mac hmac;
        private BigInteger p, q, g, x;
        private int qlen, rlen, rolen, holen;
        private byte[] bx;
        
        public static void main(String []args) {
            System.out.println("Hello World");
            //DeterministicDSA("SHA-256");
            DeterministicDSA hello = new DeterministicDSA("SHA-256");
            
            byte b = 123;
            hello.update(b);

            String s1 = "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED8873ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779";
            String s2 = "996F967F6C8E388D9E28D01E205FBA957A5698B1";
            String s3 = "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA417BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD";
            String s4 = "411602CB19A6CCC34494D79D98EF1E7ED5AF25F7";
            
            /*String s1 = "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44FFE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE235567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA153E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B";
            String s2 = "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F";
            String s3 = "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C46A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7";
            String s4 = "69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC";*/
            
            BigInteger one = new BigInteger(s1, 16);
            BigInteger two = new BigInteger(s2, 16);
            BigInteger three = new BigInteger(s3, 16);
            BigInteger four = new BigInteger(s4, 16);
            hello.setPrivateKey(one, 
            		            two, 
            		            three, 
            		            four);
            
            byte[] bb;
            
            /*
             * bb = hello.sign();

            String string2;
            
            string2 = hello.toHexString(bb);

            System.out.println("signature:"+ string2);
            */
            
            //start time
            long startTime = System.nanoTime();  
            for(int i = 0;i<100;i++)
            {
                bb = hello.sign();
              
            }
            //consume time
            long consumingTime = System.nanoTime() - startTime; 
            System.out.println(consumingTime);
            System.out.println(consumingTime/1000+"us");
            System.out.println(consumingTime/100000+"once/us");
            
        }
        
        /**
        /* turn byteArray to hexstring
        * @param byteArray
           
        * @return hexstring
        **/
       
       public static String toHexString(byte[] byteArray)
       {
       	  if (byteArray == null || byteArray.length < 1)
       	   throw new IllegalArgumentException("this byteArray must not be null or empty");
       	 
       	  final StringBuilder hexString = new StringBuilder();
       	  for (int i = 0; i < byteArray.length; i++)
       	  {
       	   if ((byteArray[i] & 0xff) < 0x10)//it is not zero before 0~F 
       	    hexString.append("0");
       	   hexString.append(Integer.toHexString(0xFF & byteArray[i]));
       	  }
       	  return hexString.toString().toLowerCase();
       }
        
        
        
        /**
         * Create an instance, using the specified hash function. The
         * name is used to obtain from the JVM an implementation of
         * the hash function, and an implementation of HMAC.
         *
         * @param hashName   the hash function name
         * @throws IllegalArgumentException  on unsupported name
         */
                       
        public DeterministicDSA(String hashName)
        {
                try {
                        dig = MessageDigest.getInstance(hashName);
                } catch (NoSuchAlgorithmException nsae) {
                        throw new IllegalArgumentException(nsae);
                }
                if (hashName.indexOf('-') < 0) {
                        macName = "Hmac" + hashName;
                } else {
                        StringBuilder sb = new StringBuilder();
                        sb.append("Hmac");
                        int n = hashName.length();
                        for (int i = 0; i < n; i ++) {
                                char c = hashName.charAt(i);
                                if (c != '-') {
                                        sb.append(c);
                                }
                        }
                        macName = sb.toString();
                }
                try {
                        hmac = Mac.getInstance(macName);
                } catch (NoSuchAlgorithmException nsae) {
                        throw new IllegalArgumentException(nsae);
                }
                holen = hmac.getMacLength();
        }

        /**
         * Set the private key.
         *
         * @param p   key parameter: field modulus
         * @param q   key parameter: sub-group order
         * @param g   key parameter: generator
         * @param x   private key
         */
        public void setPrivateKey(BigInteger p, BigInteger q,
                BigInteger g, BigInteger x)
        {
                /*
                 * Perform some basic sanity checks. We do not
                 * check primality of p or q because that would
                 * be too expensive.
                 *
                 * We reject keys where q is longer than 999 bits,
                 * because it would complicate signature encoding.
                 * Normal DSA keys do not have a q longer than 256
                 * bits anyway.
                 */
                if (p == null || q == null || g == null || x == null
                        || p.signum() <= 0 || q.signum() <= 0
                        || g.signum() <= 0 || x.signum() <= 0
                        || x.compareTo(q) >= 0 || q.compareTo(p) >= 0
                        || q.bitLength() > 999
                        || g.compareTo(p) >= 0 || g.bitLength() == 1
                        || g.modPow(q, p).bitLength() != 1) {
                        throw new IllegalArgumentException(
                                "invalid DSA private key");
                }
                this.p = p;
                this.q = q;
                this.g = g;
                this.x = x;
                qlen = q.bitLength();
                if (q.signum() <= 0 || qlen < 8) {
                        throw new IllegalArgumentException(
                                "bad group order: " + q);
                }
                rolen = (qlen + 7) >>> 3;
                rlen = rolen * 8;

                /*
                 * Convert the private exponent (x) into a sequence
                 * of octets.
                 */
                bx = int2octets(x);
        }

        private BigInteger bits2int(byte[] in)
        {
                BigInteger v = new BigInteger(1, in);
                int vlen = in.length * 8;
                if (vlen > qlen) {
                        v = v.shiftRight(vlen - qlen);
                }
                return v;
        }

        private byte[] int2octets(BigInteger v)
        {
                byte[] out = v.toByteArray();
                if (out.length < rolen) {
                        byte[] out2 = new byte[rolen];
                        System.arraycopy(out, 0,
                                out2, rolen - out.length,
                                out.length);
                        return out2;
                } else if (out.length > rolen) {
                        byte[] out2 = new byte[rolen];
                        System.arraycopy(out, out.length - rolen,
                                out2, 0, rolen);
                        return out2;
                } else {
                        return out;
                }
        }

        private byte[] bits2octets(byte[] in)
        {
                BigInteger z1 = bits2int(in);
                BigInteger z2 = z1.subtract(q);
                return int2octets(z2.signum() < 0 ? z1 : z2);
        }

        /**
         * Set (or reset) the secret key used for HMAC.
         *
         * @param K   the new secret key
         */
        private void setHmacKey(byte[] K)
        {
                try {
                        hmac.init(new SecretKeySpec(K, macName));
                } catch (InvalidKeyException ike) {
                        throw new IllegalArgumentException(ike);
                }
        }

        /**
         * Compute the pseudo-random k for signature generation,
         * using the process specified for deterministic DSA.
         *
         * @param h1   the hashed message
         * @return  the pseudo-random k to use
         */
        private BigInteger computek(byte[] h1)
        {
                /*
                 * Convert hash value into an appropriately truncated
                 * and/or expanded sequence of octets. The private
                 * key was already processed (into field bx[]).
                 */
                byte[] bh = bits2octets(h1);

                /*
                 * HMAC is always used with K as key.
                 * Whenever K is updated, we reset the
                 * current HMAC key.
                 */

                /* step b. */
                byte[] V = new byte[holen];
                for (int i = 0; i < holen; i ++) {
                        V[i] = 0x01;
                }

                /* step c. */
                byte[] K = new byte[holen];
                setHmacKey(K);

                /* step d. */
                hmac.update(V);
                hmac.update((byte)0x00);
                hmac.update(bx);
                hmac.update(bh);
                K = hmac.doFinal();
                setHmacKey(K);

                /* step e. */
                hmac.update(V);
                V = hmac.doFinal();

                /* step f. */
                hmac.update(V);
                hmac.update((byte)0x01);
                hmac.update(bx);
                hmac.update(bh);
                K = hmac.doFinal();
                setHmacKey(K);

                /* step g. */
                hmac.update(V);
                V = hmac.doFinal();

                /* step h. */
                byte[] T = new byte[rolen];
                for (;;) {
                        /*
                         * We want qlen bits, but we support only
                         * hash functions with an output length
                         * multiple of eight; hence, we will gather
                         * rlen bits, i.e. rolen octets.
                         */
                        int toff = 0;
                        while (toff < rolen) {
                                hmac.update(V);
                                V = hmac.doFinal();
                                int cc = Math.min(V.length,
                                        T.length - toff);
                                System.arraycopy(V, 0, T, toff, cc);
                                toff += cc;
                        }
                        BigInteger k = bits2int(T);
                        if (k.signum() > 0 && k.compareTo(q) < 0) {
                                return k;
                        }

                        /*
                         * k is not in the proper range; update
                         * K and V, and loop.
                         */
                        hmac.update(V);
                        hmac.update((byte)0x00);
                        K = hmac.doFinal();
                        setHmacKey(K);
                        hmac.update(V);
                        V = hmac.doFinal();
                }
        }

        /**
         * Process one more byte of input data (message to sign).
         *
         * @param in   the extra input byte
         */
        public void update(byte in)
        {
                dig.update(in);
        }

        /**
         * Process some extra bytes of input data (message to sign).
         *
         * @param in   the extra input bytes
         */
        public void update(byte[] in)
        {
                dig.update(in, 0, in.length);
        }

        /**
         * Process some extra bytes of input data (message to sign).
         *
         * @param in    the extra input buffer
         * @param off   the extra input offset
         * @param len   the extra input length (in bytes)
         */
        public void update(byte[] in, int off, int len)
        {
                dig.update(in, off, len);
        }

        /**
         * Produce the signature. {@link #setPrivateKey} MUST have
         * been called. The signature is computed over the data
         * which was input through the {@code update*()} methods.
         * This engine is then reset (made ready for a new
         * signature generation).
         *
         * @return  the signature
         */
        public byte[] sign()
        {
                return signHash(dig.digest());
        }

        /**
         * <p>Produce the signature. {@link #setPrivateKey} MUST have
         * been called. The signature is computed over the provided
         * hash value (data is assumed to have been hashed
         * externally). The data which which was input through the
         * {@code update*()} methods is ignored, but kept.</p>
         *
         * <p>If the hash output is longer than the subgroup order
         * (the length of q, in bits, denoted 'qlen'), then the
         * provided value {@code h1} can be truncated, provided that
         * at least qlen leading bits are preserved. In other words,
         * bit values in {@code h1} beyond the first qlen bits are
         * ignored.</p>
         *
         * @param h1   the hash value
         * @return  the signature
         */
        public byte[] signHash(byte[] h1)
        {
                if (p == null) {
                        throw new IllegalStateException(
                                "no private key set");
                }
                try {
                        BigInteger k = computek(h1);
                        BigInteger r = g.modPow(k, p).mod(q);
                        BigInteger s = k.modInverse(q).multiply(
                                bits2int(h1).add(x.multiply(r)))
                                .mod(q);

                        /*
                         * Signature encoding: ASN.1 SEQUENCE of
                         * two INTEGERs. The conditions on q
                         * imply that the encoded version of r and
                         * s is no longer than 127 bytes for each,
                         * including DER tag and length.
                         */
                        byte[] br = r.toByteArray();
                        byte[] bs = s.toByteArray();
                        int ulen = br.length + bs.length + 4;
                        int slen = ulen + (ulen >= 128 ? 3 : 2);
                        byte[] sig = new byte[slen];
                        int i = 0;
                        sig[i ++] = 0x30;
                        if (ulen >= 128) {
                                sig[i ++] = (byte)0x81;
                                sig[i ++] = (byte)ulen;
                        } else {
                                sig[i ++] = (byte)ulen;
                        }
                        sig[i ++] = 0x02;
                        sig[i ++] = (byte)br.length;
                        System.arraycopy(br, 0, sig, i, br.length);
                        i += br.length;
                        sig[i ++] = 0x02;
                        sig[i ++] = (byte)bs.length;
                        System.arraycopy(bs, 0, sig, i, bs.length);
                        return sig;

                } catch (ArithmeticException ae) {
                        throw new IllegalArgumentException(
                                "DSA error (bad key ?)", ae);
                }
        }

        /**
         * Reset this engine. Data input through the {@code
         * update*()} methods is discarded. The current private key,
         * if one was set, is kept unchanged.
         */
        public void reset()
        {
                dig.reset();
        }
}

