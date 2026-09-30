/**
 * SCAMSHIELD AI - Demo Scenarios & Test Presets
 * Used strictly to populate input fields for hackathon evaluator convenience.
 * The authoritative score is ALWAYS computed dynamically by the backend API.
 */

const DEMO_PRESETS = [
  {
    id: "preset-electricity",
    label: "⚡ Urgent Electricity Disconnection Notice",
    category: "Utility Impersonation",
    message: "Dear Consumer, your electricity bill is unpaid. Power supply will be disconnected tonight at 9:30 PM. Immediately call officer Sharma at 9876543210 or click http://quick-power-bill-pay.xyz/update to verify payment.",
    url: "http://quick-power-bill-pay.xyz/update",
    upiId: "discom.verify92@okaxis",
    amount: "₹ 1,450",
    reason: "Electricity Bill Payment"
  },
  {
    id: "preset-lottery",
    label: "🎁 Lottery / Reward UPI 'Collect' Trap",
    category: "Collect Request Trap",
    message: "Congratulations! You have won a cash reward of Rs. 25,000 from KBC Lucky Draw. To receive your prize in your bank, accept the payment collect request in your UPI app and enter your PIN now.",
    url: "http://reward-claim-kbc2026.online/winner",
    upiId: "prize.disbursement.dept@paytm",
    amount: "₹ 25,000",
    reason: "Prize Claim"
  },
  {
    id: "preset-bank-kyc",
    label: "🏦 Bank KYC / ₹2 Verification Trap",
    category: "Credential Phishing",
    message: "Your SBI NetBanking profile is suspended due to pending KYC update. Pay nominal verification fee of Rs 2 immediately to reactivate your account.",
    url: "http://sbi-kyc-verify-portal.top/auth",
    upiId: "sbi.kyc.desk@ybl",
    amount: "₹ 2",
    reason: "Account Reactivation Verification"
  },
  {
    id: "preset-job-task",
    label: "💼 Work From Home / YouTube Rating Task",
    category: "Job / Task Scam",
    message: "Part-time job offer! Earn Rs 3000 to 5000 daily from home just by liking YouTube videos. Deposit Rs 1000 prepaid registration charge to activate your daily payout account.",
    url: "https://bit.ly/earn-daily-tasks-2026",
    upiId: "globaltask.payouts@okaxis",
    amount: "₹ 1,000",
    reason: "Prepaid Task Registration"
  },
  {
    id: "preset-legit",
    label: "🛒 Legitimate Local Grocery Purchase",
    category: "Routine Commerce",
    message: "Your bill at Fresh Daily Supermart is Rs 340. Thank you for shopping with us. Invoice has been saved to your account.",
    url: "https://freshdailygrocers.com/receipt/4921",
    upiId: "freshdaily.store@okhdfcbank",
    amount: "₹ 340",
    reason: "Grocery Purchase"
  }
];

if (typeof window !== "undefined") {
  window.DEMO_PRESETS = DEMO_PRESETS;
}
