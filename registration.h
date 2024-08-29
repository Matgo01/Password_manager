#ifndef REGISTRATION_H
#define REGISTRATION_H

#include <QDialog>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QMessageBox>
#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include "EncryptionManager.h"

class Registration : public QDialog{
    Q_OBJECT

    public:
       Registration(QWidget *parent=nullptr);
       ~Registration();

    private slots:

       void RegistrationDialog();

    private:
       QLineEdit *username;
       QLineEdit *password;
       QVBoxLayout *layout;
       QPushButton *registration;
       EncryptionManager *encryptionManager;
       QSqlDatabase db;
       

};

#endif
