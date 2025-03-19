return {
    jwt_secret = "your_secret_key",
    credentials = {
        { key = "expected_key1", secret = "expected_secret1" },
        { key = "expected_key2", secret = "expected_secret2" },

    },
    port_map = {
        lab1 = "http://app1:8081",
        lab2 = "http://app2:8082"
    }
}