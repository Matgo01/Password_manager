#include "login.h"

Login::Login(QWidget *parent):QDialog(parent){
    setWindowTitle("Login");
    layout = new QVBoxLayout(this);

    usernameEdit = new QLineEdit(this);
    usernameEdit->setPlaceholderText("enter username");
    layout->addWidget(usernameEdit);

    passwordEdit = new QLineEdit(this);
    passwordEdit->setEchoMode(QLineEdit::Password);
    passwordEdit->setPlaceholderText("enter password");
    layout->addWidget(passwordEdit);

    loginButton = new QPushButton("Login", this);
    layout->addWidget(loginButton);

    connect(loginButton, &QPushButton::clicked, this, onLoginClieck());

    // Setup MySQL connection
        db = QSqlDatabase::addDatabase("QMYSQL");
        db.setHostName("localhost");
        db.setDatabaseName("password_manager");
        db.setUserName("your_username");
        db.setPassword("your_password");

        if (!db.open()) {
            QMessageBox::critical(this, "Database Connection Error", "Failed to connect to the database.");
            exit(1);
        }
}

Login::~LoginDialog() {
        db.close();
        delete encryptionManager;
    }

Login::onLoginClicked(){
    if(validateCredentials()){
        accept();
    }else{
        QMessageBox::warning(this, "Error", "Invalid username or password.");
    }
}

Login::validateCredentials(){
   QString enteredUsername = usernameEdit->text();
   QString enteredPassword = passwordEdit->text();

   if(enteredUsername.isEmpty() || enteredPassword.isEmpty()){
       QMessageBox::warning(this, "Input error","Username or passoword cannot be empty");
       return false;
   }

   QSlqQuery query;
   query.prepare("SELECT username, password FROM users WHERE username = :username");
   std::string encryptedUsername = encryptedManager->encrypt(enteredUsername.toStdString());
   query.bindValue(":username", QString::fromStdString(encryptedUsername));

   if(query.exec() && query.next()){
    std::string encryptedPassword = query.value("password").toString().toStdString();
    std::string decryptedPassword = encryptedManager->decrypt(encryptedPassword);

    std::string dbDecryptedUsername = EncryptionManager->decrypt(dbEncryptedUsername);
    std::string dbDecryptedPassword = encryptionManager->decrypt(dbEncryptedPassword);

            // Validate against user input
    if (enteredUsername.toStdString() == dbDecryptedUsername && enteredPassword.toStdString() == dbDecryptedPassword) {
        return true;
     }
   }
   return false;
    
}