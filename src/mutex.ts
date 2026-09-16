export class Mutex {
  #lock = Promise.resolve();

  async lock() {
    let release = () => {};
    const lock = this.#lock;
    this.#lock = new Promise((resolve) => {
      release = resolve;
    });
    await lock;
    return release;
  }
}
