<?php
header('Content-Type: application/json');

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = strip_tags(trim($_POST["name"]));
    $email = filter_var(trim($_POST["email"]), FILTER_SANITIZE_EMAIL);
    $message = trim($_POST["message"]);

    if (empty($name) || empty($message) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        http_response_code(400);
        echo json_encode(["success" => false, "message" => "Proszę prawidłowo wypełnić wszystkie pola."]);
        exit;
    }

    // Zabezpieczający wczyt parametrów konfiguracyjnych
    $config_path = __DIR__ . '/config.php';
    if (!file_exists($config_path)) {
        http_response_code(500);
        echo json_encode(["success" => false, "message" => "Błąd krytyczny: Brak pliku konfiguracyjnego serwera."]);
        exit;
    }
    $config = require $config_path;

    $to = $config['recipient'];
    $subject = "Nowe zapytanie ze strony od: $name";
    
    // Konfiguracja pobrana bezpiecznie z pliku
    $smtp_host = $config['smtp_host'];
    $smtp_port = $config['smtp_port'];
    $smtp_user = $config['smtp_user'];
    $smtp_pass = $config['smtp_pass'];
    
    $crlf = "\r\n";
    
    // Nagłówki wiadomości E-mail
    // Nazwa nadawcy (imię i nazwisko z formularza), Email Autoryzowany (żeby uniknąć odrzucenia przez filtry SPF)
    $headers = "From: =?UTF-8?B?" . base64_encode($name) . "?= <$smtp_user>" . $crlf;
    $headers .= "Reply-To: $email" . $crlf;
    $headers .= "MIME-Version: 1.0" . $crlf;
    $headers .= "Content-Type: text/plain; charset=UTF-8" . $crlf;
    
    // Treść wiadomości w e-mailu
    $body = "Otrzymano nowe zapytanie ze strony xByte.\n\n";
    $body .= "Imię i Nazwisko: $name\n";
    $body .= "Adres Email: $email\n\n";
    $body .= "Treść Wiadomości:\n$message\n";
    
    // Parametry połączenia SSL
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false
        ]
    ]);
    
    // Połączenie z serwerem pocztowym SMTP autoryzacji
    $socket = stream_socket_client($smtp_host . ":" . $smtp_port, $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
    
    if (!$socket) {
        http_response_code(500);
        echo json_encode(["success" => false, "message" => "Błąd połączenia z serwerem pocztowym SMTP ($errstr)."]);
        exit;
    }
    
    function server_parse($socket, $response) {
        $server_response = '';
        while (substr($server_response, 3, 1) != ' ') {
            if (!($server_response = fgets($socket, 256))) {
                throw new Exception("Problem z odczytem ze strumienia serwera SMTP.");
            }
        }
        if (!(substr($server_response, 0, 3) == $response)) {
            throw new Exception("Błąd serwera. Oczekiwano $response, otrzymano: $server_response");
        }
    }
    
    try {
        server_parse($socket, "220");
        
        $http_host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost';
        fwrite($socket, "EHLO " . $http_host . $crlf);
        server_parse($socket, "250");
        
        fwrite($socket, "AUTH LOGIN" . $crlf);
        server_parse($socket, "334");
        
        fwrite($socket, base64_encode($smtp_user) . $crlf);
        server_parse($socket, "334");
        
        fwrite($socket, base64_encode($smtp_pass) . $crlf);
        server_parse($socket, "235");
        
        fwrite($socket, "MAIL FROM: <$smtp_user>" . $crlf);
        server_parse($socket, "250");
        
        fwrite($socket, "RCPT TO: <$to>" . $crlf);
        server_parse($socket, "250");
        
        fwrite($socket, "DATA" . $crlf);
        server_parse($socket, "354");
        
        $email_content = "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=" . $crlf;
        $email_content .= $headers . $crlf;
        $email_content .= $body . $crlf;
        $email_content .= "." . $crlf;
        
        fwrite($socket, $email_content);
        server_parse($socket, "250");
        
        fwrite($socket, "QUIT" . $crlf);
        fclose($socket);
        
        echo json_encode(["success" => true, "message" => "Wiadomość została wysłana."]);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(["success" => false, "message" => "Wystąpił błąd podczas autoryzacji lub wysyłania protokołem SMTP: " . $e->getMessage()]);
    }
} else {
    http_response_code(405);
    echo json_encode(["success" => false, "message" => "Nieobsługiwana metoda żądania HTTP."]);
}
?>
