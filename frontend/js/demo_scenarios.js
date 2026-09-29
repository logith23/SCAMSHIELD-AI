/**
 * SCAMSHIELD AI - Demo Presets (Simulated Hackathon Data)
 * No real banking or financial accounts.
 */

const DEMO_PRESETS = [
  {
    id: "preset-electricity",
    label: "⚡ Electricity Disconnection Fraud",
    category: "Utility Impersonation",
    message: "Dear Consumer, your electricity bill is unpaid. Power will be disconnected tonight at 9:30 PM. Immediately call officer Sharma at 9876543210 or click http://quick-power-bill-pay.xyz/update to verify payment.",
    url: "http://quick-power-bill-pay.xyz/update",
    upiId: "discom.verify92@okaxis",
    amount: "₹ 1,450",
    simulatedScore: 88,
    simulatedVerdict: "CRITICAL RISK",
    triggers: [
      "Artificial extreme urgency (power cutoff in hours)",
      "Unverified third-party domain (.xyz)",
      "Personal VPA acting as official utility entity"
    ]
  },
  {
    id: "preset-lottery",
    label: "🎁 Lottery / UPI 'Collect' Deception",
    category: "Collect Request Trap",
    message: "Congratulations! You have won Rs 25,000 cash prize in National Lucky Draw. To receive amount, accept the payment collect request in your UPI app and enter your PIN now.",
    url: "http://reward-claim-portal2026.online/winner",
    upiId: "prize.disbursement.dept@paytm",
    amount: "₹ 25,000",
    simulatedScore: 94,
    simulatedVerdict: "CRITICAL RISK",
    triggers: [
      "Classic PIN inversion trick: Claims entering PIN receives money",
      "Suspicious top-level domain (.online)",
      "Unsolicited prize or lottery claim"
    ]
  },
  {
    id: "preset-legit",
    label: "🛒 Legitimate Local Merchant",
    category: "Safe Verified Transaction",
    message: "Your grocery invoice at Green Mart has been generated. Total payable: ₹ 420. Thank you for your visit.",
    url: "https://greenmart-grocers.com/receipt/5810",
    upiId: "greenmart.billing@okhdfcbank",
    amount: "₹ 420",
    simulatedScore: 8,
    simulatedVerdict: "SAFE TRANSACTION",
    triggers: [
      "No coercive language or psychological manipulation",
      "Standard merchant payment pattern",
      "Encrypted HTTPS legitimate domain"
    ]
  }
];

if (typeof window !== "undefined") {
  window.DEMO_PRESETS = DEMO_PRESETS;
}
