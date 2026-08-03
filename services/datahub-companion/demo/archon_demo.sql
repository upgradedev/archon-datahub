PRAGMA foreign_keys = ON;

CREATE TABLE customers (
  customer_id INTEGER PRIMARY KEY,
  customer_email TEXT NOT NULL UNIQUE,
  segment TEXT NOT NULL CHECK (segment IN ('enterprise', 'mid_market', 'small_business')),
  country_code TEXT NOT NULL,
  consent_status TEXT NOT NULL CHECK (consent_status IN ('granted', 'withdrawn'))
);

CREATE TABLE orders (
  order_id INTEGER PRIMARY KEY,
  customer_id INTEGER NOT NULL REFERENCES customers(customer_id),
  recognized_at TEXT NOT NULL,
  gross_revenue_cents INTEGER NOT NULL CHECK (gross_revenue_cents >= 0)
);

CREATE TABLE refunds (
  refund_id INTEGER PRIMARY KEY,
  order_id INTEGER NOT NULL REFERENCES orders(order_id),
  recognized_at TEXT NOT NULL,
  refund_cents INTEGER NOT NULL CHECK (refund_cents >= 0)
);

INSERT INTO customers
  (customer_id, customer_email, segment, country_code, consent_status)
VALUES
  (1, 'ada@example.invalid', 'enterprise', 'GR', 'granted'),
  (2, 'grace@example.invalid', 'enterprise', 'DE', 'granted'),
  (3, 'linus@example.invalid', 'mid_market', 'FI', 'granted'),
  (4, 'margaret@example.invalid', 'small_business', 'US', 'withdrawn');

INSERT INTO orders
  (order_id, customer_id, recognized_at, gross_revenue_cents)
VALUES
  (101, 1, '2026-04-15T10:00:00Z', 1200000),
  (102, 2, '2026-06-30T23:59:59Z', 800000),
  (103, 3, '2026-05-20T12:00:00Z', 1400000),
  (104, 4, '2026-06-01T09:00:00Z', 600000),
  (105, 1, '2026-07-01T00:00:00Z', 999999),
  (106, 3, '2026-03-31T23:59:59Z', 999999);

INSERT INTO refunds
  (refund_id, order_id, recognized_at, refund_cents)
VALUES
  (201, 101, '2026-04-20T09:00:00Z', 100000),
  (202, 102, '2026-06-30T23:59:59Z', 50000),
  (203, 103, '2026-05-28T15:00:00Z', 250000),
  (204, 105, '2026-07-02T00:00:00Z', 999999);

CREATE VIEW customer_segment_revenue AS
WITH q2_orders AS (
  SELECT order_id, customer_id, gross_revenue_cents
  FROM orders
  WHERE recognized_at >= '2026-04-01T00:00:00Z'
    AND recognized_at < '2026-07-01T00:00:00Z'
),
q2_refunds AS (
  SELECT order_id, SUM(refund_cents) AS refund_cents
  FROM refunds
  WHERE recognized_at >= '2026-04-01T00:00:00Z'
    AND recognized_at < '2026-07-01T00:00:00Z'
  GROUP BY order_id
)
SELECT
  c.segment AS segment,
  COUNT(DISTINCT c.customer_id) AS customer_count,
  SUM(o.gross_revenue_cents - COALESCE(r.refund_cents, 0)) AS net_revenue_cents
FROM q2_orders AS o
JOIN customers AS c ON c.customer_id = o.customer_id
LEFT JOIN q2_refunds AS r ON r.order_id = o.order_id
GROUP BY c.segment;