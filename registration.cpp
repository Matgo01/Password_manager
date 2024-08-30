#include "registration.h"

Registration::Registration(QWidget *parent):QDialog(parent){
    setWindowTitle("registration");
    layout = new QVBoxLayout(this);
    
    username = new QLineEdit(this);
    username->setPlaceholderText("username");
    layout->addWidget(username);

    password = new QLineEdit(this);
    password->setEchoMode(QLineEdit::Password);
    password->setPlaceholderText("password");
    layout->addWidget(password);

    registerButton = new QPushButton("Register", this);
    layout->addWidget(registerButton);

    connect(registerButton,QPushButton::cliecked,this,Registration);

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

Registration::~Registration() {
        db.close();
        delete encryptionManager;
    }

Registration::RegistrationDialog(){
    QString enteredUsername = username->text();
    QString enteredPassword = password->text();

    if(entereUsername.isEmpty() || enteredPassword.isEmpty()){
        QMessageBox::warnings(this, "Input error","Username or passoword cannot be empty");
       return;
    }

     std::string encryptedUsername = encryptionManager-> encrypt(username.toStdString());
     std::string encryptedPassword = encryptionManager->encrypt(password.toStdString());

    QSqlquery query;
        query.prepare("INSERT INTO passwords (username, password) VALUES (:username, :password)");
        query.bindValue(":username", QString::fromStdString(encryptedUsername));
        query.bindValue(":password", QString::fromStdString(encryptedPassword));

        if (query.exec())
        {
            QMessage::information(this, "Succes","Username and password save successufully");
            usernameEdit->clear();
            passwordEdit->clear();
        }else{
            QMessageBox::critical(this, "Error", "Failed to save the password.");
        }

}
