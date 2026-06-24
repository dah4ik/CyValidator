CREATE TABLE IF NOT EXISTS demo_customers (
                                              id SERIAL PRIMARY KEY,
                                              customer_ref VARCHAR(50) NOT NULL,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(120) NOT NULL,
    classification VARCHAR(50) NOT NULL
    );

CREATE TABLE IF NOT EXISTS demo_security_notes (
                                                   id SERIAL PRIMARY KEY,
                                                   note_title VARCHAR(150) NOT NULL,
    note_body TEXT NOT NULL,
    risk_level VARCHAR(50) NOT NULL
    );

INSERT INTO demo_customers (customer_ref, full_name, email, classification)
VALUES
    ('CUST-DEMO-001', 'Demo Customer One', 'demo.customer.one@example.local', 'sensitive-demo'),
    ('CUST-DEMO-002', 'Demo Customer Two', 'demo.customer.two@example.local', 'sensitive-demo'),
    ('CUST-DEMO-003', 'Demo Customer Three', 'demo.customer.three@example.local', 'internal-demo')
    ON CONFLICT DO NOTHING;

INSERT INTO demo_security_notes (note_title, note_body, risk_level)
VALUES
    (
        'Database Exposure Simulation',
        'This database is intentionally exposed on localhost:15432 for CyValidator lab validation only.',
        'High'
    ),
    (
        'Segmentation Control Gap',
        'The lab simulates a database that should be reachable only from application zones.',
        'Critical'
    )
    ON CONFLICT DO NOTHING;