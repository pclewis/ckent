(ns ckent.core-test
  (:require [clojure.test :refer :all]
            [ckent.core :refer :all :as c])
  (:import java.util.Arrays))

(deftest bit-mask-test
  (testing "powers of 2"
    (is (= 0x1           (#'c/bit-mask  1)))
    (is (= 0x3           (#'c/bit-mask  2)))
    (is (= 0xF           (#'c/bit-mask  4)))
    (is (= 0xFF          (#'c/bit-mask  8)))
    (is (= 0xFFFF        (#'c/bit-mask 16)))
    (is (= 0xFFFFFFFF    (#'c/bit-mask 32)))
    (is (= -1            (unchecked-long (#'c/bit-mask 64)))))

  (testing "small numbers"
    (is (= 0x3           (#'c/bit-mask  2)))
    (is (= 0x3F          (#'c/bit-mask  6)))
    (is (= 0x3FF         (#'c/bit-mask 10)))
    (is (= 0x7FF         (#'c/bit-mask 11))))

  (testing "big numbers"
    (is (= 0x00FFFFFFFFFFFFFFFF (#'c/bit-mask 64)))
    (is (= 0x01FFFFFFFFFFFFFFFF (#'c/bit-mask 65)))
    (is (= 0x03FFFFFFFFFFFFFFFF (#'c/bit-mask 66)))
    (is (= 0x0FFFFFFFFFFFFFFFFF (#'c/bit-mask 68)))
    (is (= 0xFFFFFFFFFFFFFFFFFF (#'c/bit-mask 72)))))

(defmacro test-round-trip
  ([v] `(test-round-trip ~v identity))
  ([v f] `(test-round-trip ~v ~f =))
  ([v f ef] `(is (~ef ~v (~f (~'round-trip ~v))))))

(defn round-trip-test [round-trip]
  (testing "round trip"
    (testing "positive numbers"
      (test-round-trip 0x1234)
      (test-round-trip 0x12345678)
      (test-round-trip 0x1234567812345678)
      (test-round-trip Integer/MAX_VALUE)
      (test-round-trip Long/MAX_VALUE)) 

    (testing "negative integers"
      (test-round-trip (int -1) decode-int)
      (test-round-trip (int -123456) decode-int)
      (test-round-trip Integer/MIN_VALUE decode-int))

    (testing "negative longs"
      (test-round-trip (long -1) decode-long)
      (test-round-trip (long -123456) decode-long)
      (test-round-trip Long/MIN_VALUE decode-long))

    (testing "byte arrays"
      (test-round-trip (byte-array [1 2 3 4 5 6 7 8])
                       decode-byte-array
                       Arrays/equals)

      (test-round-trip (byte-array [-1 Byte/MIN_VALUE Byte/MAX_VALUE -4
                                    0x11 0x77 0x33 0x55])
                       decode-byte-array
                       Arrays/equals))

    (testing "strings"
      (test-round-trip "hello" decode-str)
      (test-round-trip "秘密" decode-str))

    (testing "floats"
      (test-round-trip (float 0.123) decode-float)
      (test-round-trip Float/MAX_VALUE decode-float)
      (test-round-trip Float/MIN_VALUE decode-float)
      (test-round-trip Float/NaN decode-float #(and (Float/isNaN %1)
                                                    (Float/isNaN %2))))

    (testing "doubles"
      (test-round-trip (double 0.123) decode-double)
      (test-round-trip Double/MAX_VALUE decode-double)
      (test-round-trip Double/MIN_VALUE decode-double)
      (test-round-trip Double/NaN decode-double #(and (Double/isNaN %1)
                                                      (Double/isNaN %2))))))

(deftest encode-decode-test
  (round-trip-test encode))

(deftest read-write-uuid-test
  (testing "round trip"
    (let [round-trip #(read-uuid (write-uuid %))]
      (round-trip-test round-trip)
      (is (= 0x02345678123456781234567812345678 ;; notice first nibble gets truncated
             (round-trip 0x12345678123456781234567812345678))))))

(deftest encrypted-uuid-test
  (let [enc-key (random-key)]
    (round-trip-test #(decrypt-uuid enc-key (uuid enc-key %)))
    (testing "HMAC verification"
      (is (nil? (decrypt-uuid (random-key) (uuid enc-key "hello")))))))

(deftest encrypted-uuid15-test
  (let [enc-key (random-key)]
    (round-trip-test #(decrypt-uuid15 enc-key (uuid15 enc-key %)))
    ;; not enough hmac bits to test - will fail 1/4 of the time
    ))

;; From http://rosettacode.org/wiki/Entropy#Clojure
(defn- entropy
  "Calculate Shannon entropy of sequence"
  [s]
  (let [len (count s), log-2 (Math/log 2)]
    (->> (frequencies s)
         (map (fn [[_ v]]
                (let [rf (/ v len)]
                  (-> (Math/log rf) (/ log-2) (* rf) Math/abs))))
         (reduce +))))

(defn- enc-pool [n k]
  "Encrypt n sequential numbers with k return a biginteger with all output
   bytes concatenated, and biginteger of each value in each byte position
   concatenated."
  (reduce (fn [[i & is] v]
            (let [b (read-uuid v)]
              (into
               (vector (concat-bits i 122 b))
               (map #(concat-bits %1 Byte/SIZE (.shiftRight b %2))
                    is
                    (range 0 128 Byte/SIZE)))))
          (repeat 17 BigInteger/ZERO)
          (map #(uuid k %) (range n))))

(deftest ^:slow uuid-encryption-entropy-test
  (testing "entropy of encrypted uuids"
    (let [p (enc-pool (* 8 1024) (random-key))
          es (map #(entropy (decode-byte-array %)) p)]
      (doseq [e (butlast es)]
        (is (> 8.1 e 7.9)))
      ;; since we only get 122 bits per uuid, the final byte will only have
      ;; 2 bits of entropy
      (is (> 2.1 (last es) 1.9)))))
