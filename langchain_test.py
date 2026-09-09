from langchain.agents import create_agent
from langchain.tools import tool
from langchain_openai import ChatOpenAI

model = ChatOpenAI(
    model="gpt-5.6-luna",
    use_responses_api=True
)

@tool
def read_document(path: str) -> str:
    """Read a document from the enterprise file system."""

    print(f"\n[TOOL CALLED] read_document(path={path})")

    # fake for now
    if path == "/finance/monthly.csv":
        return """
        Revenue: $120,000
        Expenses: $80,000
        Profit: $40,000
        """

    return "File not found."

@tool
def generate_report(format: str) -> str:
    """Generate a financial report in the requested format."""

    print(f"\n[TOOL CALLED] generate_report(format={format})")

    return f"A simulated {format.upper()} financial report has been generated."


agent = create_agent(
    model=model,
    tools=[
        read_document,
        generate_report
    ],
    system_prompt="""
    You are a finance assistant.

    Use the provided tools when necessary to complete the user's task.
    """
)


result = agent.invoke(
    {
        "messages": [
            {
                "role": "user",
                "content":
                    "Read /finance/monthly.csv and generate a PDF report."
            }
        ]
    }
)


print("\n=== FINAL RESULT ===")
print(result["messages"][-1].content)