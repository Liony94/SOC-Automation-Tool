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
                            description=f"Niveau de risque global: **{data.get('risk_level', 'Unknown').upper()}**",
                            color=discord.Color.blue()
                        )
                        
                        # Ajout des résultats d'analyse
                        analysis = data.get("analysis", {})
                        vt_analysis = analysis.get("virustotal", {})
                        embed.add_field(
                            name="VirusTotal",
                            value=f"Niveau de risque: {vt_analysis.get('risk_level', 'Unknown').upper()}\nDétections: {vt_analysis.get('detection_ratio', '0/0')}",
                            inline=False
                        )
                        
                        # Ajout des résultats AbuseIPDB
                        abuse_analysis = analysis.get("abuseipdb", {})
                        embed.add_field(
                            name="AbuseIPDB",
                            value=f"Niveau de risque: {abuse_analysis.get('risk_level', 'Unknown').upper()}\nScore de confiance: {abuse_analysis.get('confidence_score', 0)}%",
                            inline=False
                        )
                        
                        # Ajout des recommandations
                        recommendations = data.get("recommendations", [])
                        if recommendations:
                            embed.add_field(
                                name="Recommandations",
                                value="\n".join(f"• {rec}" for rec in recommendations),
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