-- 01_create_schema.sql
-- Creates the SAAOWNER user and the three tables reconstructing the
-- documented SWIFT Alliance Access schema (column names sourced from
-- BAE Systems 2016 and the DOJ complaint). Run as SYS, inside XEPDB1.
--
-- NOTE: the _01 suffix is a lab placeholder. BAE's documented SQL uses
-- an undocumented wildcard (MESG_%s) -- the real suffix is unknown.
-- MESG_CREATE_DATE is a synthetic lab-convenience column, not a
-- documented field.

CREATE USER SAAOWNER IDENTIFIED BY "SentryLab_2026!";
GRANT CONNECT, RESOURCE, DBA TO SAAOWNER;
ALTER USER SAAOWNER QUOTA UNLIMITED ON USERS;

-- Connect as SAAOWNER before running the CREATE TABLE statements below.

CREATE TABLE MESG_01 (
    MESG_S_UMID               VARCHAR2(50)  PRIMARY KEY,
    MESG_SENDER_SWIFT_ADDRESS VARCHAR2(20),
    MESG_TRN_REF              VARCHAR2(50),
    MESG_FIN_CCY_AMOUNT       NUMBER(18,2),
    MESG_CREATE_DATE          DATE DEFAULT SYSDATE
);

CREATE TABLE TEXT_01 (
    TEXT_S_UMID     VARCHAR2(50)  PRIMARY KEY,
    TEXT_DATA_BLOCK CLOB,
    FOREIGN KEY (TEXT_S_UMID) REFERENCES MESG_01(MESG_S_UMID)
);

CREATE TABLE JRNL_01 (
    JRNL_ID           NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    JRNL_DISPLAY_TEXT VARCHAR2(200),
    JRNL_DATE_TIME    TIMESTAMP DEFAULT SYSTIMESTAMP
);
