-- 03_insert_dummy_data.sql
-- Populates the schema with realistic-looking dummy transactions so
-- the tables aren't empty before running attack simulations. Run as
-- SAAOWNER.

INSERT INTO MESG_01 VALUES ('UMID00001', 'TESTBANKXXX', 'TRN2026081001', 15000.00, SYSDATE);
INSERT INTO MESG_01 VALUES ('UMID00002', 'TESTBANKXXX', 'TRN2026081002', 87000.50, SYSDATE);

INSERT INTO TEXT_01 VALUES ('UMID00001', 'FIN 900 Confirmation of Debit ... Sender : TESTBANKXXX ... 20: Transaction TRN2026081001');
INSERT INTO TEXT_01 VALUES ('UMID00002', 'FIN 900 Confirmation of Debit ... Sender : TESTBANKXXX ... 20: Transaction TRN2026081002');

INSERT INTO JRNL_01 (JRNL_DISPLAY_TEXT) VALUES ('LT TESTBANKXXX: Login');
INSERT INTO JRNL_01 (JRNL_DISPLAY_TEXT) VALUES ('LT TESTBANKXXX: Logout');

COMMIT;
