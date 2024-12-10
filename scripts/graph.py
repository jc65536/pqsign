from matplotlib.gridspec import GridSpec
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from matplotlib.colors import LinearSegmentedColormap
from numpy.typing import NDArray

buf_size = np.arange(100, 2100, 100)
delay = np.arange(0, 200, 10)

delay, buf_size = np.meshgrid(delay, buf_size)

time_client_caching = np.load("../out/client-caching-tls.npy")
time_plain = np.load("../out/plain-tls.npy")
time_pqc = np.load("../out/pqc-tls.npy")
time_caching = np.load("../out/pqc-with-caching.npy")

tmax = max(time_plain.max(), time_pqc.max(), time_caching.max())

cmap = LinearSegmentedColormap.from_list("my_cmap", (
    (0, "#ff00ff"),
    (0.05, "#0000ff"),
    (0.1, "#00ff00"),
    (0.2, "#ffff00"),
    (1, "#ff0000"),
))


def make_fig(data: NDArray, title: str):
    fig, ax = plt.subplots(subplot_kw={"projection": "3d"})
    ax: Axes3D

    surf = ax.plot_surface(delay, buf_size, data,
                           cmap=cmap, vmin=0, vmax=tmax)

    ax.set_xlabel("Latency (ms)")
    ax.set_ylabel("Bandwidth (bytes)")
    ax.set_zlabel("Handshake time (ms)")
    ax.set_zlim3d(0, 10000)
    ax.view_init(azim=135)
    ax.set_title(title)

    return fig, surf


fig_plain, _ = make_fig(time_plain, "Classical algorithm")
fig_pqc, _ = make_fig(time_pqc, "Post-quantum algorithm")
fig_client_caching, _ = make_fig(time_client_caching, "Post-quantum algorithm and client-side caching")
fig_caching, surf = make_fig(time_caching, "Post-quantum algorithm and server-side caching")

fig_cb, cax = plt.subplots()
fig_cb.set_figwidth(0.5)
fig_cb.colorbar(surf, cax=cax)

fig_plain.tight_layout()
fig_plain.savefig("../out/fig_plain.png")
fig_pqc.tight_layout()
fig_pqc.savefig("../out/fig_pqc.png")
fig_caching.tight_layout()
fig_caching.savefig("../out/fig_caching.png")
fig_client_caching.tight_layout()
fig_client_caching.savefig("../out/fig_client_caching.png")
fig_cb.savefig("../out/fig_cb.png", bbox_inches="tight")
