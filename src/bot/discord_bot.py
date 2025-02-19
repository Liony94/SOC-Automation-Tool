import discord
from discord.ext import commands
import aiohttp
from src.core.config import settings
import logging

# Configuration des logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecurityBot(commands.Bot):
    def __init__(self):
        intents = discord.Intents.default()
        intents.message_content = True
        logger.info("Initialisation du bot Discord...")
        super().__init__(command_prefix='!', intents=intents)
        
    async def setup_hook(self):
        logger.info("Configuration des commandes...")
        await self.add_cog(SecurityCommands(self))
        
    async def on_ready(self):
        logger.info(f'{self.user} est connecté et prêt!')

class SecurityCommands(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.api_base_url = "http://api:8000/api/v1"

    @commands.command(name="ping")
    async def ping(self, ctx):
        """Simple commande pour tester si le bot répond"""
        logger.info("Commande ping reçue")
        await ctx.send("Pong! 🏓")

    @commands.command(name="check-ip")
    async def check_ip(self, ctx, ip_address: str):
        """Vérifie une adresse IP suspecte"""
        async with aiohttp.ClientSession() as session:
            try:
                payload = {"ip_address": ip_address}
                logger.info(f"Envoi de la requête à l'API avec payload: {payload}")
                async with session.post(
                    f"{self.api_base_url}/enrichment/check-ip",
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Création d'un embed Discord pour une meilleure présentation
                        embed = discord.Embed(
                            title=f"Analyse de l'IP: {ip_address}",
                            color=discord.Color.blue()
                        )
                        
                        # Ajout des résultats VirusTotal
                        vt_results = data.get("virustotal_results", {})
                        embed.add_field(
                            name="VirusTotal",
                            value=f"Score de détection: {vt_results.get('positives', 0)}/{vt_results.get('total', 0)}",
                            inline=False
                        )
                        
                        # Ajout des résultats AbuseIPDB
                        abuse_results = data.get("abuseipdb_results", {})
                        embed.add_field(
                            name="AbuseIPDB",
                            value=f"Score d'abus: {abuse_results.get('abuseConfidenceScore', 0)}%",
                            inline=False
                        )
                        
                        await ctx.send(embed=embed)
                    else:
                        error_text = await response.text()
                        logger.error(f"Erreur API: Status {response.status}, Response: {error_text}")
                        await ctx.send(f"Erreur lors de la vérification de l'IP: {response.status}\nDétails: {error_text}")
            except Exception as e:
                logger.error(f"Exception lors de la vérification de l'IP: {str(e)}")
                await ctx.send(f"Une erreur est survenue: {str(e)}")

def run_bot():
    logger.info("Démarrage du bot Discord...")
    bot = SecurityBot()
    bot.run(settings.DISCORD_TOKEN)

if __name__ == "__main__":
    logger.info("Script principal du bot Discord démarré")
    run_bot() 