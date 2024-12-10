package com.example.encryption;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

/**
 * EncryptionController는 사용자가 입력한 데이터를 AES 암호화 방식으로 암호화하여
 * 결과를 반환하는 역할을 합니다.
 */
@Controller
public class EncryptionController {

    private final SecretKey secretKey; // AES 암호화를 위한 비밀 키

    /**
     * 생성자: AES 암호화에 사용할 비밀 키를 생성합니다.
     *
     * @throws Exception 암호화 키 생성 예외 처리
     */
    public EncryptionController() throws Exception {
        // AES 알고리즘을 사용하여 비밀키 생성
        this.secretKey = KeyGenerator.getInstance("AES").generateKey();
    }

    /**
     * 로그인 페이지로 이동하는 GET 요청을 처리하는 메서드입니다.
     *
     * @return "login" - 로그인 페이지 (login.html)
     */
    @GetMapping("/") // 루트 경로로 들어오는 GET 요청을 처리
    public String showLoginPage() {
        return "login"; // templates/login.html 파일을 반환
    }

    /**
     * 사용자가 입력한 사용자 이름과 비밀번호를 AES 방식으로 암호화하고,
     * 암호화된 정보를 result 페이지에 전달합니다.
     *
     * @param username 사용자가 입력한 사용자 이름
     * @param password 사용자가 입력한 비밀번호
     * @param model    결과를 담아서 뷰에 전달하기 위한 모델 객체
     * @return "result" - 암호화된 비밀번호를 표시하는 페이지
     * @throws Exception 암호화 예외 처리
     */
    @PostMapping("/encrypt") // 로그인 폼이 제출되면 호출되는 POST 요청 처리
    public String encrypt(
            @RequestParam("username") String username, // 요청에서 username 가져오기
            @RequestParam("password") String password, // 요청에서 password 가져오기
            Model model // 결과를 HTML에 전달하기 위한 모델 객체
    ) throws Exception {
        // 비밀키를 Base64로 인코딩하여 출력
        String base64SecretKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println("Secret Key (Base64 Encoded): " + base64SecretKey);

        // 사용자 이름과 비밀번호를 AES 방식으로 암호화
        String encryptedUsername = encrypt(username);
        String encryptedPassword = encrypt(password);

        // 암호화된 정보를 모델에 추가하여 결과 페이지로 전달
        model.addAttribute("encryptedUsername", encryptedUsername);
        model.addAttribute("encryptedPassword", encryptedPassword);

        // 결과 페이지로 이동
        return "result";
    }

    /**
     * 문자열을 AES 알고리즘을 사용해 암호화하는 메서드입니다.
     *
     * @param plainText 암호화할 원본 텍스트
     * @return 암호화된 텍스트(Base64로 인코딩됨)
     * @throws Exception 암호화 예외 처리
     */
    private String encrypt(String plainText) throws Exception {
        // AES 암호화 알고리즘을 사용하기 위한 Cipher 객체 생성
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey); // 암호화 모드로 초기화
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes()); // 암호화 수행

        // 암호화된 바이트 배열을 Base64로 인코딩하여 문자열로 반환
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}