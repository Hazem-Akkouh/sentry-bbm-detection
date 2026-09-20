-- update_balance.sql
-- Reproduces the balance-manipulation UPDATE technique. Run as
-- SAAOWNER. Validates Rule 4.

UPDATE MESG_01 SET MESG_FIN_CCY_AMOUNT = 999999.99 WHERE MESG_S_UMID = 'UMID00002';
UPDATE TEXT_01 SET TEXT_DATA_BLOCK = 'FIN 900 Confirmation of Debit ... Sender : TESTBANKXXX ... 19A: Amount 999999.99'
  WHERE TEXT_S_UMID = 'UMID00002';
COMMIT;
