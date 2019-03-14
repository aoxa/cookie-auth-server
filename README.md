Simple cookie creation web server using Spring Boot.

run with ./gradlew build && java -jar build/libs/gs-spring-boot-0.1.0.jar 

the key used is:
SecretKeySpec keySpec = new SecretKeySpec("abcdefghijklmnopponmlkjihgfedcba".getBytes(), "AES");

the cookie created is:
new Cookie("AUTH_ID", Base64.getEncoder().encodeToString(iv) + Base64.getEncoder().encodeToString(cipher.doFinal("hello!".getBytes())));

It will redirect the user to localhost:8080/users/login.html once that is done.