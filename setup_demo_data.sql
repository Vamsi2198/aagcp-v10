-- Demo data for the aagcp real-warehouse console.
-- Run in a Snowflake worksheet. Creates DEMO_DB.PUBLIC.CUSTOMERS with
-- realistic personal data so the scan has something to find.

CREATE DATABASE IF NOT EXISTS DEMO_DB;
USE DATABASE DEMO_DB;
USE SCHEMA PUBLIC;

CREATE OR REPLACE TABLE CUSTOMERS (
    ID NUMBER PRIMARY KEY,
    FULL_NAME VARCHAR,
    EMAIL VARCHAR,
    MOBILE VARCHAR,
    DATE_OF_BIRTH DATE,
    AADHAAR_NUMBER VARCHAR,
    PAN VARCHAR,
    NOTES VARCHAR
);

INSERT INTO CUSTOMERS VALUES
(1, 'Aarav Sharma',  'aarav.sharma@gmail.com',   '9876543210', '1988-03-14', '2345 6789 0123', 'AXTPS1234K', 'premium customer'),
(2, 'Priya Patel',   'priya.p@gmail.com',        '9123456780', '1992-07-22', '3456 7890 1234', 'BZTYQ5678L', 'asked for callback'),
(3, 'Rohan Mehta',   'rohan.m@outlook.com',      '9988776655', '1985-11-30', '4567 8901 2345', 'CMUVW9012M', NULL),
(4, 'Sneha Iyer',    'sneha.iyer@yahoo.com',     '9090909090', '1995-01-05', '5678 9012 3456', 'DQRXZ3456N', 'newsletter opt-in'),
(5, 'Vikram Nair',   'vikram.nair@gmail.com',    '9345678120', '1979-09-17', '6789 0123 4567', 'ESYAB6789P', 'churn risk'),
(6, 'Ananya Reddy',  'ananya.reddy@gmail.com',   '9112233445', '1990-12-25', '7890 1234 5678', 'FTWCD0123Q', NULL),
(7, 'Karan Kapoor',  'karan.k@gmail.com',        '9567834210', '1983-05-09', '8901 2345 6789', 'GUVEF4567R', 'referred by #5'),
(8, 'Divya Menon',   'divya.menon@gmail.com',    '9001122334', '1998-08-14', '9012 3456 7890', 'HWXGH8901S', 'student discount');

SELECT COUNT(*) FROM CUSTOMERS;
