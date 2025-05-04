<?php
require 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nome = $_POST['nome'] ?? '';
    $email = $_POST['email'] ?? '';
    $senha = $_POST['senha'] ?? '';
    $tipo = $_POST['tipo'] ?? '';

    if (empty($nome) || empty($email) || empty($senha) || empty($tipo)) {
        header('Location: index.html?erro=campos_vazios');
        exit;
    }

    // Validação básica de email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        header('Location: index.html?erro=email_invalido');
        exit;
    }

    try {
        // Verifica se o email já existe
        $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
        $stmt->execute([$email]);

        if ($stmt->fetch()) {
            header('Location: index.html?erro=email_existente');
            exit;
        }

        // Hash da senha
        $senhaHash = password_hash($senha, PASSWORD_DEFAULT);

        // Insere o novo usuário
        $stmt = $pdo->prepare("INSERT INTO usuarios (nome, email, senha, tipo_usuario) VALUES (?, ?, ?, ?)");
        $stmt->execute([$nome, $email, $senhaHash, $tipo]);

        // Redireciona para a página de login com mensagem de sucesso
        header('Location: index.html?sucesso=cadastro_concluido');
        exit;
    } catch (PDOException $e) {
        header('Location: index.html?erro=erro_banco_dados');
        exit;
    }
} else {
    header('Location: index.html');
    exit;
}
?>