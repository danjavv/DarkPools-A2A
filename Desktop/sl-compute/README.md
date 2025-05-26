## Distributed Sahamati Queries

- Query 1: How many times did the user purchase x product (e.g. mobile recharging) from this platform and what was the average order value?

    - File: `product_average.rs`

- Query 2: Average order value for each of the last $x$ months (Total order value / Number of orders)

    - File: `average_monthly_order.rs`

- Query 3: Is the major delivery address same as registered address in bank document? What are the addresses for each?

    - File: `delivery_address.rs`

- Query 4: How many users's have an average monthly credit over amount *threshold_credit* and average monthly amazon spend over *threshold_spend*?

    - File: `average_monthly_credit.rs`

- Query 5: Refund rate of a customer for the last $3$ months combined - Total orders refunded by user/ (Total orders purchased - total returned due to platform's reasons)

    - File: `refund_rate.rs`