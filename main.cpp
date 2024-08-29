#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include "EncryptionManager.h"
#include "LoginDialog.h" 

class PasswordManagerApp : QWidget{
    Q_OBJECT
    
    public:
      PasswordManagerApp(QWidget *parent=nullptr):QWidget(parent){
        QVBoxLayout *layout = new QVBoxLayout(this);

        userNameEdit = new QLineEdit(this);
        usernameEdit->setPlaceholderText("Enter username to Sava");
        layout->addWidget(userNameEdit);

        passwordEdit = new QLineEdit(this);
        passwordEdit->setEchoMode(QLineEdit::Password);
        passwordEdit->setPlaceholderText("Enter password to Save");
        layout->addWidget(passwordEdit);

        saveButton = new QPushButton("Save", this);
        saveButton->setDefault(true);
        layout->addWidget(saveButton);

        retriveUsernameEdit = new QLineEdit(this);
        retriveUsernameEdit->setPlaceholderText("enter username to retrive password");
        layout->addWidget(retriveUsernameEdit);

        QPushButton *retriveButton = new QPushButton("retrive password");
        layout->addWidget(retriveButton);

        connect(saveButton, &QPushButton::clicked, this, &PasswordManagerApp::savePassword);
        connect(retriveButton, &QPushButton::clicked, this, &PasswordManagerApp::retrivePassword);

        db = QSqlDatabase::addDatabase("QMYSQL");
        db.setHostName("localhost");
        db.setDatabaseName("password_manager");
        db.setUserName("your_username");
        db.setPassword("your_password");

        if (!db.open()) {
            QMessageBox::critical(this, "Database Connection Error", "Failed to connect to the database.");
            exit(1);
        }

        encryptionManager = new EncryptionManager("your_master_password");

      }

      ~PasswordManagerApp() {
        db.close();
        delete encryptionManager;
    }

    private slots:
       void onSavedClicked(){
        QString username = username->text();
        QSrring password = password->text();
        
        if(username.isEmpty()) || password.isEmpty(){
            QMessageBox::critical(this, "Error", "Please fill all the fields.");
            return;
        }

        std::string encryptedUsername = encryptionManager-> encrypt(username.toStdStrin());
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

       void onRetriveClicked(){
        QString username = retriveUsernameEdit->text();
        
        if(username.isEmpty()){
            QMessageBox::critical(this, "Error", "Please enter the username.");
            return;
        }
        
        std::string encryptedUsername = encryptionManager->encrypt(username.toStdString());
        QSqlQuery query;
        query.prepare("SELECT password FROM passwords WHERE username = :username");
        query.bindValue(":username", QString::fromStdString(encryptedUsername));
        
        if (query.exec() && query.next()){
            std::string encryptedPassword = query.value(0).toString().toStdString();
            std::string decryptedPassword = encryptionManager->decrypt(query.value(0).toString().toStdString());
            QMessageBox::information(this, "Password", QString::fromStdString(decryptedPassword));
        }else{
            QMessageBox::critical(this, "Error", "Failed to retrieve the password.");
        }
       }

    private:
        QLineEdit *usernameEdit;
        QLineEdit *passwordEdit;
        QLineEdit *retrieveUsernameEdit;
        QSqlDatabase db;
        EncryptionManager *encryptionManager;
};

int main(int argc, char *argv[]){
    QApplication app(argc, argv);
    LoginDialog loginDialog;
    if (loginDialog.exec() == QDialog::Accepted) {
        PasswordManagerApp window;
        window.show();
        return app.exec();
    }else{
        RegistratationDialog registrationDialog;
    }
    return 0;
}