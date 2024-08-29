#ifndef LOGIN_H
#define LOGIN_H


#include <QDialog>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include "EncryptionManager.h"

class Login: public QDialog{

    Q_OBJECT
    
    public:
       Login(QWidgent *parent=nullptr);
       ~LoginDialog();
       
    public slots:
      void onLoginClicked();
      bool validateCredentials();

    private:
      QLineEdit *usernameEdit;
      QLineEdit *passwordEdit;
      QPushButton *loginButton;
      QVBoxLayout *layout;
      QSqlDatabase db;
      EncryptionManager *encryptionManager;

    
};

#endif