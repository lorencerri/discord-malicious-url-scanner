require("dotenv").config();

// Discord.js
const { Client, Intents, MessageEmbed } = require("discord.js");
const intents = [Intents.FLAGS.GUILDS, Intents.FLAGS.GUILD_MESSAGES];
const client = new Client({ intents });

const linkify = require("linkifyjs"); // Linkify (Scans text for URLs)
const VirusTotalAPI = require("virustotal-api"); // VirusTotal (Scans URLs)
const virusTotal = new VirusTotalAPI(process.env.VT_API_KEY);

// Message Handler
client.on("messageCreate", async (message) => {
    if (message.author.bot) return;
    const senderId = message.author.id;

    // Match URLs in message
    const urls = linkify
        .find(message.content)
        .filter((i) => i.type === "url")
        .filter((i) => !i.value.startsWith("https://discord.com/")) // ignore discord links
        .filter((i) => !i.value.endsWith(".png")) // ignore png images
        .filter((i) => !i.value.endsWith(".mp4")); // ignore mp4 videos
        // ignoring certain files isn't necessary, it's only to ensure VirusTotal ratelimits aren't met

    for (var i = 0; i < urls.length; i++) {

        const url = urls[i].value;
        console.log(`Scanning ${url}`);

        // Catch Rate Limit Errors
        var result;
        try {
            result = await virusTotal.urlReport(url, false, 1);
        } catch (err) {}

        // Positive Results
        if (result && result.positives > 0) {
            
            // Delete Message
            message.delete();

            // Ban Member
            message.member.ban({ days: 1, reason: `Sent potentially malicious URL. ${result.permalink}` })

            // Create Alert
            const embed = new MessageEmbed()
                .setTitle("Malicious URL Detected")
                .setColor(0x5865f2)
                .setURL(result.permalink)
                .setDescription(
                    `🔗 \`${url}\`\nScan Date: \`${result.scan_date}\``
                )
                .addField(
                    "Positives",
                    `\`${result.positives}/${result.total}\``,
                    true
                )
                .addField("Sender", `<@${senderId}> \`(${senderId})\``, true);

            // Send Alert
            message.guild.channels.cache
                .get("398491167005868043")
                .send({ embeds: [embed] });
            
            break;
        }
    }
});

// Ready Event
client.on("ready", () => {
    console.log(`Logged in as ${client.user.username}`);
});

// Login
client.login(process.env.DISCORD_TOKEN);
