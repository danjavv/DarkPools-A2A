import asyncio
from compare_ge.compare_ge_wrapper import CompareGEWrapper

async def main():
    # Create wrapper instance
    wrapper = CompareGEWrapper()
    
    # Initialize the MPC environment
    await wrapper.initialize()
    
    # Single comparison
    result = await wrapper.compare_ge(5, 3)
    print(f"5 >= 3: {result}")  # Should print True
    
    # Batch comparison
    x_values = [5, 10, 3]
    y_values = [3, 15, 3]
    results = await wrapper.batch_compare_ge(x_values, y_values)
    print(f"Batch results: {results}")  # Should print [True, False, True]

if __name__ == "__main__":
    asyncio.run(main()) 