# A $223 Million Mistake: Lessons from the Cetus Protocol Overflow Bug

## Context

The Cetus Protocol hack highlights a growing frontier in cybersecurity: **smart contract security in decentralized finance (DeFi)**. As traditional cybersecurity professionals begin encountering threats in blockchain systems, it's critical to understand how foundational Web3 components work. This section introduces the key technical and architectural concepts needed to grasp the exploit in question.

### How Smart Contracts Work

In Web3 ecosystems, **smart contracts** are immutable programs deployed on a blockchain. Once deployed, these contracts are publicly accessible, and their code is visible to all—anyone can interact with them by sending transactions. This introduces a **trustless paradigm** where the code itself enforces rules, rather than institutions or administrators.

However, the **immutability** and **permissionless accessibility** of smart contracts also increase the risk: if there's a bug, anyone can exploit it, and it can't be patched in place. This puts a premium on secure-by-design coding, extensive audits, formal verification, and community-based defenses like bug bounty programs.

### Decentralized Exchanges and AMMs

Cetus Protocol is a **concentrated liquidity Automated Market Maker (AMM)** inspired by Uniswap v3. AMMs are decentralized exchanges (DEXs) where users trade assets based on mathematical formulas rather than order books. Liquidity providers deposit token pairs into pools and earn fees, while traders swap assets against the pool’s reserves.

In Uniswap v3 and its derivatives, liquidity is not evenly spread across the price range. Instead, it's **concentrated in "ticks"**—discrete price intervals. This improves capital efficiency but also introduces **complex mathematical operations** (often involving square roots and high-precision arithmetic) for calculating liquidity, token deltas, and fee distribution.

### Flashloans

The hack also relied on a mechanism called a **flashloan**—a type of loan that lets users borrow large amounts of crypto **without collateral**, as long as they repay it within the same blockchain transaction. If repayment doesn’t happen, the entire transaction is reverted. While powerful for arbitrage and liquidation use cases, flashloans are also a common tool in attacks since they allow temporary access to massive capital.

### Integer Overflows and Precision Arithmetic

Just like in traditional systems, blockchain programs can suffer from **integer overflows**, but the consequences are amplified due to the irreversible and financial nature of blockchain operations. In DeFi protocols, overflow vulnerabilities often occur during **fixed-point arithmetic** used to simulate decimals on platforms (like Move or Solidity) that don't support floating-point types.

In this exploit, a poorly implemented overflow check in a function handling 256-bit arithmetic allowed the attacker to **trick the system into thinking they provided significant liquidity when they did not**. This is a typical example of a **logic bug** that passed superficial audits but had catastrophic financial implications.

## Technical Issue

The vulnerability lies in the following function that calculates the amount of token A (ΔA) to be swapped in a liquidity range:
```rust
get_delta_a(p0: u128, p1: u128, L: u128, round_up: bool): u64 {
    let v0 = if (p0 > p1) { p0 - p1 } else { p1 - p0 };
    if (v0 == 0 || L == 0) { return 0 };

    // 1) full precision multiply into a 256-bit intermediate
    let (prod, _) = full_mul(L, v0);             // u256 = L × |p1–p0|
    // 2) shift left by 64 bits (to scale by 2^64)
    let (shifted, overflow) = checked_shlw(prod);
    if (overflow) { abort 2 };

    // 3) divide by p0*p1, rounding
    div_round(shifted, full_mul(p0, p1), round_up) as u64
}
```

This function implements the formula:

```math
\Delta A = \left\lfloor \frac{L \cdot |p_1 - p_0| \cdot 2^{64}}{p_0 \cdot p_1} \right\rfloor 
\quad \text{or} \quad 
\left\lceil \frac{L \cdot |p_1 - p_0| \cdot 2^{64}}{p_0 \cdot p_1} \right\rceil 
\quad \text{if } \texttt{round\_up} = \texttt{true}
```

This formula is standard in protocols inspired by Uniswap v3, where token prices are represented as **square roots** and liquidity is distributed across **ticks**, or price intervals. Each tick represents a different minimum price interval. The constant `2^64` (about 10**19)  is a scaling factor that ensures high-precision calculation using integer arithmetic.

The issue exploited by the attacker was located in this helper function:

```rust
/// perform a left bitwise shift by 64 bits on a u256 value. 
/// Returns a tuple containing the shifted value and a boolean indicating if the operation 
/// would overflow.
public fun checked_shlw(arg0: u256): (u256, bool) {
    // which equals to 0xFFFFFFFFFFFFFFFF << 192
    let max_value: u256 = 115792089237316195417293883273301227089434195242432897623355228563449095127040; 

    if (arg0 > max_value) {
        (0, true)
    } else {
        (arg0 << 64, false)
    }
}
```
The vulnerability is in the **overflow check**. The threshold (`max_value`) was incorrectly set to a much larger number than it should be. It checks whether `arg0 > (2^64 – 1) << 192`, but **overflow actually occurs when `arg0 >= 1 << 192`**. This mistake means the check allows unsafe values to be shifted left by 64 bits without triggering the overflow flag, producing an incorrect but seemingly valid result.

## How the Hacker Exploited the Bug

The entire attack was carried out within a **single transaction using a flashloan**, a type of instant loan that must be repaid in the same transaction. If not, the entire transaction fails and is reverted. This lets attackers temporarily borrow large sums of money with no upfront capital.

Here’s how the exploit unfolded:

1)   **Borrowed tokens using a flashloan**:  
    The attacker initiated a flashloan, borrowing around **20.4 trillion tokens** and **~556 billion SUI tokens** without any upfront cost.
    
2)   **Chose a specific liquidity range**:  
    They created a liquidity position between **tick 300,000 and tick 300,200**, where the token amount calculation formula and logic from the vulnerable function would be triggered.
    
3)  **Deposited a tiny amount of tokens**:  
    The attacker deposited just **1 unit of the token (SCA)**—the absolute minimum.
    
	Under normal circumstances, this deposit would yield negligible liquidity. But due to the flawed overflow check, a critical math operation returned a very small number instead of reverting. This tricked the contract into thinking the attacker had provided **a large amount of liquidity**, when in fact they had deposited almost nothing. Here’s a simplified view of the math:

    3.1) Calculated liquidity over those ticks.
  
    3.2) Calculated actual "$`\text{amount}_{token}`$" required for liquidity provision based on same formula above, skip the formula here.
  
    3.3) When calculating actual "$`\text{amount}_{token}`$", the numerator part "$`L*(\sqrt{P_{\text{high}}} - \sqrt{P_{\text{low}}})`$" failed overflow check. <br><br>
 ```math
 L = \frac{\text{amount}_{token} \cdot \sqrt{P_{\text{low}}} \cdot \sqrt{P_{\text{high}}}}{\sqrt{P_{\text{high}}} - \sqrt{P_{\text{low}}}}
 ```
<br>
     

The bug caused the numerator of the formula to **underflow after a left shift**, making the final required token amount near-zero. As a result, the attacker deposited **1 token** and received access to **massive theoretical liquidity**.

4. **Withdrew the inflated liquidity**:  
After the system accepted their fraudulent liquidity position, the attacker quickly **removed liquidity**, **repaid the flashloan**, and kept the rest of the tokens.

5. **Repeated the process**:  
The attacker ran this same process multiple times to fully drain the pool.

## Lessons for Cybersecurity Engineers


Smart contracts are **public and immutable**, meaning their source code is visible and executable by anyone. This openness brings both benefits (auditability, transparency) and risks (attackers can study code deeply to find edge-case bugs). Here are key takeaways:

1.  **Open-source vulnerabilities are everyone's problem**  
    Since Web3 contracts are open by default, any oversight becomes a public weakness. This hack is a reminder that attackers may understand the code more thoroughly than the developers or auditors.
    
2.  **Overflow and precision issues remain dangerous**  
    Integer overflow—familiar to traditional developers—continues to be a top issue in DeFi. When combined with complex formulas involving high-precision math, these bugs can silently cause massive financial losses.
    
3.  **Audit reports are not silver bullets**  
    Cetus did go through security audits by recognized (though not top-tier) firms. However, these firms **missed the overflow flaw**. Audits often focus on typical misuse patterns or large financial flows, but attackers dig deeper.
    
4.  **Bug bounty programs must be funded properly**  
    Despite having **high Total Value Locked (TVL)**, Cetus did not allocate a significant budget for bug bounty rewards. If better incentives had been offered, a white-hat hacker might have found and responsibly disclosed the vulnerability.


## References
- [news source](https://www.securityweek.com/223-million-stolen-in-cetus-protocol-hack/)
-  [cetus's report](https://cetusprotocol.notion.site/Cetus-Incident-Report-May-22-2025-Attack-Disclosure-1ff1dbf3ac8680d7a98de6158597d416)
- [rekt news](https://rekt.news/cetus-rekt)
- [slowmist analysis](https://slowmist.medium.com/slowmist-analysis-of-the-230-million-cetus-hack-ee569af040f2)
- [dedaub analysis](https://dedaub.com/blog/the-cetus-amm-200m-hack-how-a-flawed-overflow-check-led-to-catastrophic-loss/)

