(ns ckent.core
  (:import clojure.lang.BigInt
           java.security.Key
           java.security.MessageDigest
           java.security.SecureRandom
           java.util.Arrays
           java.util.UUID
           javax.crypto.Cipher
           javax.crypto.KeyGenerator
           javax.crypto.Mac
           javax.crypto.spec.IvParameterSpec))

(def ^String CHARSET "UTF-8")
(def ^String CIPHER "Blowfish/ECB/NoPadding")
(def ^String KEYGEN "Blowfish")
(def ^String KEYSIZE 448)
(def ^String MAC "HmacSHA256")

;; Dealing with byte arrays:
;;   For type hints, use ^"[B"
;;     ^bytes works sometimes, but as a return type hint it refers to
;;     clojure.core/bytes and doesn't always throw an error.
;; [B class object for multimethod dispatch:
(def ^Class ByteArray (Class/forName "[B"))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Bit packing
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- bit-mask
  "Return a BigInteger with lowest n-bits set"
  [n]
  (-> BigInteger/ONE
      (.shiftLeft n)
      (.subtract BigInteger/ONE)))

(defn- take-last-bits
  "Return lowest n bits of i"
  [n i]
  (.and (biginteger i)
        (bit-mask n)))

(defmulti ^BigInteger encode
  "Encode a value as an unsigned (non-negative) BigInteger.
  NOTE: leading zeroes in variable-length values (ex byte arrays or strings)
        cannot be encoded - you must know the original length to properly
        decode them."
  (fn [v] (class v)))

(defn encode*
  "Return the positive BigInteger with the same bits set as the two's complement
  representation of v in the given number of bits.
  Ex: (encode* 8  -1) = 0xFF   = 255
      (encode* 16 -1) = 0xFFFF = 65535"
  [n-bits v]
  (if (neg? v)
    (.xor (.not (biginteger v)) (bit-mask n-bits))
    (biginteger v)))

(defmethod encode BigInteger [v] (assert (not (neg? v))) v)
(defmethod encode BigInt     [v] (assert (not (neg? v))) (biginteger v))
(defmethod encode Byte       [v] (encode* Byte/SIZE    v))
(defmethod encode Short      [v] (encode* Short/SIZE   v))
(defmethod encode Integer    [v] (encode* Integer/SIZE v))
(defmethod encode Long       [v] (encode* Long/SIZE    v))
(defmethod encode Float      [v] (encode (Float/floatToRawIntBits v)))
(defmethod encode Double     [v] (encode (Double/doubleToRawLongBits v)))
(defmethod encode String     [v] (encode (.getBytes ^String v CHARSET)))
(defmethod encode ByteArray  [v] (BigInteger. 1 ^"[B" v))

;; A decode multimethod would be more symmetrical, but passing a type as an
;; argument is awkward, and multiple fns seems more idiomatic.
;; (see ex byte, int, short, bigint, *-array, unchecked-*, etc)

(defn ^"[B" decode-byte-array
  "Convert a BigInteger to a ByteArray. Same as BigInteger.toByteArray, except
  without a leading zero for the sign bit when the highest bit is on a byte
  boundary.
  i.e.:  (.toByteArray (biginteger 0x80)) => [0, 0x80]
  but  : (decode-byte-array (biginteger 0x80)) => [0x80]"
  [^BigInteger i]
  (let [ba (.toByteArray i)]
    (if (zero? (first ba))
      (Arrays/copyOfRange ba 1 (count ba))
      ba)))

(defn decode-str
  "Convert a BigInteger to a String."
  [^BigInteger i]
  (String. (decode-byte-array i) CHARSET))

(def decode-bigint bigint)

(def decode-byte   unchecked-byte)
(def decode-short  unchecked-short)
(def decode-int    unchecked-int)
(def decode-long   unchecked-long)

(defn decode-float  [i] (Float/intBitsToFloat    (decode-int  i)))
(defn decode-double [i] (Double/longBitsToDouble (decode-long i)))

(defn concat-bits
  "Append lowest n bits of v to i. (ret := (i<<n) | (v & MASK[n]))"
  [^BigInteger i ^Integer n v]
  (.or (.shiftLeft i n)
       (take-last-bits n (encode v))))

(defn pack
  "Create a BigInteger by packing values in m according to fmt, where
  fmt is [[n-bits keyword-or-value], ...]

  For keywords, the next n-bits of the corresponding value in m are
  used. For values, the value itself is used."
  [fmt m]
  (first
   (reduce
    (fn [[i m] [n v]]
      (if (keyword? v)
        [(concat-bits i n (v m)) (update m v #(.shiftRight (encode %) n))]
        [(concat-bits i n (encode v)) m]))
    [BigInteger/ZERO m]
    fmt)))

(defn unpack
  "Inverse of pack, i.e. recreate the original map given the same fmt and
  the value returned from pack.

  Note: values in result map will all be BigIntegers"
  [fmt i]
  (second
   (reduce
    (fn [[^BigInteger i m] [n v]]
      [(.shiftRight i n)
       (if (keyword? v)
         (update m v #(.or (.shiftLeft (or ^BigInteger % BigInteger/ZERO) n)
                           (take-last-bits n i)))
         m)])
    [i {}]
    (reverse fmt))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; UUIDs
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmethod encode UUID [^UUID v]
  (pack [[64 :hi] [64 :lo]]
        {:hi (.getMostSignificantBits v)
         :lo (.getLeastSignificantBits v)}))

(def uuid-format [[48 :i] [4 4]
                  [12 :i] [2 2]
                  [62 :i]])

(defn write-uuid
  "Create a valid V4 UUID with the lowest 122 bits of i."
  [i]
  (let [^BigInteger j (pack uuid-format {:i i})]
    (UUID. (.longValue (.shiftRight j 64))
           (.longValue j))))

(defn read-uuid
  "Return the 122 non-static bits of a V4 UUID."
  [u]
  (->> (encode u)
       (unpack uuid-format)
       (:i)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Crypto
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn ^"[B" digest*
  [^String algo ^"[B" bs]
  (-> (MessageDigest/getInstance algo)
      (.digest bs)))

(defn ^BigInteger digest
  [^String algo v]
  (->> (encode v)
       (.toByteArray)
       (digest* algo)
       (encode)))

(defn hmac*
  [^String algo ^Key k ^"[B" bs]
  (-> (doto (Mac/getInstance algo)
        (.init k))
      (.doFinal bs)))

(defn ^BigInteger hmac
  [^String algo ^Key k v]
  (->> (encode v)
       (.toByteArray)
       (hmac* algo k)
       (encode)))

(defn block-size
  "Return a cipher's block size in bytes."
  [algo]
  (.getBlockSize (Cipher/getInstance algo)))

(defn to-block
  "Return array of last n bytes from bs, LEFT padded with 0s.
  Always returns exactly n bytes."
  [^Number n ^"[B" bs]
  (->> (concat (repeat n (byte 0)) bs)
       (take-last n)
       (byte-array)))

(defn to-blocks
  "Encode v into a byte array that is a multiple of specified size, LEFT padded
  with 0 bytes if necessary."
  [size v]
  (let [i (encode v)
        n-blocks (Math/ceil (/ (.bitLength i) (* size Byte/SIZE)))]
    (to-block (* size n-blocks)
              (.toByteArray i))))

(defn ^"[B" encipher*
  [^String algo ^Key k ^IvParameterSpec iv ^"[B" bs]
  (let [c (Cipher/getInstance algo)]
    (if iv
      (.init c Cipher/ENCRYPT_MODE k iv)
      (.init c Cipher/ENCRYPT_MODE k))
    (.doFinal c bs)))

(defn ^BigInteger encipher
  ([^String algo ^Key k ^IvParameterSpec iv v] (encipher algo k iv (block-size algo) v)) 
  ([^String algo ^Key k ^IvParameterSpec iv ^Number block-size v]
   (->> (to-blocks block-size v)
        (encipher* algo k iv)
        (encode))))

(defn ^"[B" decipher*
  [^String algo ^Key k ^IvParameterSpec iv ^"[B" bs]
  (let [c (Cipher/getInstance algo)]
    (if iv
      (.init c Cipher/DECRYPT_MODE k iv)
      (.init c Cipher/DECRYPT_MODE k))
    (.doFinal c bs)))

(defn decipher
  ([^String algo ^Key k ^IvParameterSpec iv v]
   (decipher algo k iv (block-size algo) v))
  ([^String algo ^Key k ^IvParameterSpec iv ^Number block-size v]
   (->> (to-blocks block-size v)
        (decipher* algo k iv)
        (encode))))

(defn random-key
  "Randomly generate a key for use with encipher and decipher."
  ([] (random-key KEYGEN KEYSIZE))
  ([^String algo ^Integer size]
   (-> (doto (KeyGenerator/getInstance algo)
         (.init size))
       (.generateKey))))

(defn random-iv
  "Randomly generate an IV for use with encipher and decipher."
  [^String algo]
  (let [bs (byte-array (block-size algo))]
    (.nextBytes (SecureRandom.) bs)
    (IvParameterSpec. bs)))

(defn hash-iv
  "Generate an IV using the cryptographic hash of a value."
  [^String algo v]
  (let [d (digest "SHA-512" v)
        bs (to-block (block-size algo) (.toByteArray d))]
    (IvParameterSpec. bs)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Custom schemes
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- valid-format?
  [fmt]
  (and (coll? fmt)
       (not-empty fmt)
       (every? coll? fmt)
       (every? #(= 2 %) (map count fmt))
       (every? number? (map first fmt))))

(defn- fmt-size
  [fmt k]
  (->> (filter #(= k (last %)) fmt)
       (map first)
       (reduce +)))

(defn- generate-iv-seed
  [size]
  (when (pos? size)
    (let [iv-seed-bytes (byte-array (Math/ceil (/ size Byte/SIZE)))]
      (.nextBytes (SecureRandom.) iv-seed-bytes)
      (take-last-bits size (encode iv-seed-bytes)))))

(defn custom
  [{:keys [fmt key cipher mac static-iv]
    :or {mac "HmacSHA256"}}
   v]
  {:pre [(valid-format? fmt)]}
  (let [iv-size (fmt-size fmt :iv-seed)
        iv-seed (generate-iv-seed iv-size)
        iv (cond static-iv      static-iv
                 (pos? iv-size) (hash-iv cipher iv-seed))

        hmac-size (fmt-size fmt :hmac)
        hmac (when (pos? hmac-size)
               (take-last-bits hmac-size (hmac mac key v)))

        ct-bits (fmt-size fmt :ciphertext)
        ct-bytes (Math/ceil (/ ct-bits Byte/SIZE))
        ct (encipher cipher key iv ct-bytes v)]
    (assert (>= ct-bits (.bitLength ct)) "format has enough space for ciphertext")
    (pack fmt {:ciphertext ct
               :iv-seed iv-seed
               :hmac hmac})))

(defn decrypt-custom
  [{:keys [fmt key cipher mac static-iv]
    :or {mac "HmacSHA256"}}
   v]
  {:pre [(valid-format? fmt)]}
  (let [m (unpack fmt v)
        iv-size (fmt-size fmt :iv-seed)
        iv-seed (:iv-seed m)
        iv (cond static-iv      static-iv
                 (pos? iv-size) (hash-iv cipher iv-seed))

        pt-bits (fmt-size fmt :ciphertext)
        pt-bytes (Math/ceil (/ pt-bits Byte/SIZE))
        pt (take-last-bits pt-bits (decipher cipher key iv pt-bytes
                                             (:ciphertext m)))

        hmac-size (fmt-size fmt :hmac)
        hmac (when (pos? hmac-size) (take-last-bits hmac-size (hmac mac key pt)))]
    (when (or (zero? hmac-size)
              (= hmac (:hmac m)))
      pt)))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Encrypted UUIDs
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def uuid-crypt-format [[64 :ciphertext]
                        [58 :hmac]])

(defn uuid
  [k v]
  (write-uuid
   (pack uuid-crypt-format {:ciphertext (encipher CIPHER k nil v)
                            :hmac       (hmac MAC k v)})))

(defn decrypt-uuid
  [k u]
  (let [m (unpack uuid-crypt-format (read-uuid u))
        pt (decipher CIPHER k nil (:ciphertext m))
        hmac (hmac MAC k pt)]
    (when (= (:hmac m) (take-last-bits 58 hmac)) pt)))


(def uuid15-cipher "Blowfish/CTS/NoPadding")
(def uuid15-params {:fmt       [[120 :ciphertext] [2 :hmac]]
                    :static-iv (hash-iv uuid15-cipher 31337)
                    :cipher    uuid15-cipher})

(defn- mix
  "xor the lowest 56 bits of i with the next 56.

  This step ensures that, given a full 64-bit block and incomplete 56-bit block and using CTS, any change
  in the incomplete input block also affects the output of the full block. CTS already ensures that the
  full block affects the incomplete block's output, because its ciphertext is used as padding.

  This is not, as far as I am aware, any kind of standard practice, and may introduce cryptographic
  weakness."
  [i]
  (-> (take-last-bits 56 i)
      (.shiftLeft 56)
      (.xor i)))

(defn uuid15
  [k v]
  (->> (encode v)
       (mix)
       (custom (assoc uuid15-params :key k))
       (write-uuid)))

(defn decrypt-uuid15
  [k u]
  (->> (read-uuid u)
       (decrypt-custom (assoc uuid15-params :key k))
       (mix)))
