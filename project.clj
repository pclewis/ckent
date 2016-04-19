(defproject ckent "0.9.1"
  :description "Generate random UUIDs that contain encrypted data"
  :license {:name "Unlicense"
            :url "http://unlicense.org/"}
  :dependencies [[org.clojure/clojure "1.7.0"]]
  :test-selectors {:default (complement :slow)
                   :slow :slow
                   :all (constantly true)})
